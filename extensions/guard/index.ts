/**
 * Unified guard extension.
 *
 * Merges the former ask-permission, sandbox, and CARE extensions into a single
 * `tool_call` handler so bash commands flow through one ordered pipeline:
 *
 *   1. CARE grades the command (ALLOW / WARN / DENY); DENY hard-blocks.
 *   2. The active safety tier decides auto-allow vs prompt vs block
 *      (see docs/safety-tiers.md).
 *   3. Approved commands are wrapped in the bwrap sandbox (unless tier is `off`).
 *
 * Non-bash tools keep the old ask-permission behavior: reads inside the project
 * (or the configured `allowedReadDirs`) auto-allow, everything else prompts.
 */

import { existsSync, readFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve, relative, isAbsolute, sep, join } from "node:path";
import { quote } from "shell-quote";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { analyze } from "./lib/care/engine.ts";
import { resolve as resolveCare } from "./lib/care/resolution.ts";
import { formatBashCommand } from "../../lib/bash-format.ts";
import type { AnalysisResult, Decision } from "./lib/care/types.ts";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Tier = "off" | "on" | "net" | "readonly";

interface CareConfig {
  defaultTier: Tier;
  mode: "balanced" | "strict" | "auto";
  warnPolicy: "prompt" | "deny";
  allowedReadDirs: string[];
  writableDirs: string[];
  overrides: {
    allowHeads: string[];
    denyHeads: string[];
    allowPaths: string[];
    denyPaths: string[];
  };
}

const DEFAULT_CONFIG: CareConfig = {
  defaultTier: "on",
  mode: "balanced",
  warnPolicy: "prompt",
  allowedReadDirs: ["/nix", "~/.rustup", "~/.cargo"],
  writableDirs: ["~/.cargo", "~/.rustup", "~/.cache", "~/.local/share", "~/.config", "~/.npm"],
  overrides: { allowHeads: [], denyHeads: [], allowPaths: [], denyPaths: [] },
};

function loadConfig(): CareConfig {
  const path = join(homedir(), ".pi", "agent", "guard.json");
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    return {
      ...DEFAULT_CONFIG,
      ...raw,
      overrides: { ...DEFAULT_CONFIG.overrides, ...(raw.overrides ?? {}) },
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

const config = loadConfig();
let tier: Tier = config.defaultTier;

// ---------------------------------------------------------------------------
// bwrap sandbox
// ---------------------------------------------------------------------------

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p; // `~user/...` left as-is
}

function wrapInBwrap(command: string, cwd: string, t: Tier): string {
  const args: string[] = ["bwrap", "--ro-bind", "/", "/"]; // read-only root
  if (t !== "readonly") {
    args.push("--bind", cwd, cwd); // project dir writable
    for (const dir of config.writableDirs) {
      const abs = expandHome(dir);
      if (existsSync(abs)) args.push("--bind", abs, abs);
    }
  }
  args.push(
    "--dev", "/dev",
    "--proc", "/proc",
    "--tmpfs", "/tmp",
    "--tmpfs", "/var/tmp",
    ...(t === "net" ? [] : ["--unshare-net"]), // network only in the `net` tier
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--cap-drop", "ALL",
    "--die-with-parent",
    "bash", "-c", command,
  );
  return quote(args);
}

function sandboxStatus(): string | undefined {
  switch (tier) {
    case "off":
      return undefined;
    case "net":
      return "🛡 guard ON · net";
    case "readonly":
      return "🛡 guard ON · read-only";
    default:
      return "🛡 guard ON · no net";
  }
}

// ---------------------------------------------------------------------------
// read auto-allow (former ask-permission behavior)
// ---------------------------------------------------------------------------

function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

async function canonical(base: string, p: string): Promise<string> {
  const abs = resolve(base, p);
  try {
    return await realpath(abs);
  } catch {
    return abs; // doesn't exist (yet) — fall back to the lexical path
  }
}

let allowedReadRoots: string[] | undefined;
async function getAllowedReadRoots(): Promise<string[]> {
  if (!allowedReadRoots) {
    allowedReadRoots = await Promise.all(
      config.allowedReadDirs.map((dir) => canonical(expandHome(dir), ".")),
    );
  }
  return allowedReadRoots;
}

async function isReadAllowed(projectRoot: string, target: string): Promise<boolean> {
  if (isInside(await canonical(projectRoot, "."), target)) return true;
  for (const root of await getAllowedReadRoots()) {
    if (isInside(root, target)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// CARE helpers
// ---------------------------------------------------------------------------

function rawHead(cmd: string): string {
  const first = cmd.trim().split(/\s+/)[0] ?? "";
  const parts = first.split("/");
  return parts[parts.length - 1] ?? first;
}

function matchesPath(paths: string[], cmd: string): boolean {
  return paths.some((p) => p.length > 0 && cmd.includes(p));
}

/** Human-readable one-line evidence for the dialog / block reason. */
function summarize(r: AnalysisResult): string {
  const bits: string[] = [];
  const cls = r.details.semanticMaxClass;
  if (cls && cls !== "READ_ONLY") bits.push(cls.replace(/_/g, " ").toLowerCase());
  if (r.details.path.reason && r.details.path.reason !== "paths_ok") {
    bits.push(r.details.path.reason.replace(/_/g, " "));
  }
  for (const rule of r.firedRules.slice(0, 4)) bits.push(rule.description);
  return bits.length > 0 ? bits.join(" · ") : "no specific evidence";
}

/** Read-context head with no write/redirect/tee/sed -i. */
function isPureRead(cmd: string, r: AnalysisResult): boolean {
  if (r.details.semanticMaxClass !== "READ_ONLY") return false;
  if (/(?<![0-9&])>>?\s*\S/.test(cmd)) return false;
  if (/\btee\b\s+(-a\s+)?\S/.test(cmd)) return false;
  if (/\bsed\s+[^|;]*-i\b/.test(cmd)) return false;
  return true;
}

/** Narrow read-only auto-allow: clearly reading, nothing flagged, no sink. */
function isReadOnlySafe(cmd: string, r: AnalysisResult): boolean {
  if (!isPureRead(cmd, r)) return false;
  if (r.firedRules.length > 0) return false;
  if (r.details.path.score >= 0.5) return false;
  if (r.details.ast.hasPipeToExec) return false;
  return true;
}

// ---------------------------------------------------------------------------
// handlers (params mirror pi's tool_call event / context)
// ---------------------------------------------------------------------------

async function promptBash(ctx: any, cmd: string, r: AnalysisResult): Promise<boolean> {
  if (!ctx.hasUI) return false; // no human to ask — fail closed
  let preview = cmd.trim().startsWith("bwrap") ? cmd : formatBashCommand(cmd);
  if (preview.length > 1500) preview = preview.slice(0, 1500) + "\n…";
  const title = `Allow this command?\n\n${preview}\n\nFlagged: ${summarize(r)}`;
  const choice = await ctx.ui.select(title, ["Allow", "Deny"]);
  return choice === "Allow";
}

async function handleBash(event: any, ctx: any) {
  const cmd: string = event.input.command;
  const r = analyze(cmd, { mode: config.mode });
  const f = resolveCare(r);
  let decision: Decision = f.decision;

  // overrides — deny wins over allow
  const head = rawHead(cmd);
  if (config.overrides.denyHeads.includes(head) || matchesPath(config.overrides.denyPaths, cmd)) {
    decision = "DENY";
  } else if (config.overrides.allowHeads.includes(head) || matchesPath(config.overrides.allowPaths, cmd)) {
    decision = "ALLOW";
  }

  // DENY — hard block in every tier
  if (decision === "DENY") {
    return { block: true, reason: `CARE blocked (score ${r.score}): ${summarize(r)}` };
  }

  // readonly tier — write-context commands are blocked
  if (tier === "readonly" && !isPureRead(cmd, r)) {
    return { block: true, reason: "Read-only mode: command writes" };
  }

  // warnPolicy deny — treat WARN like DENY
  if (decision === "WARN" && config.warnPolicy === "deny") {
    return { block: true, reason: `CARE blocked (warn): ${summarize(r)}` };
  }

  // auto-allow: only when contained (tier !== off), for ALLOW or clearly-read WARN
  const autoAllow =
    tier !== "off" &&
    (decision === "ALLOW" || (decision === "WARN" && isReadOnlySafe(cmd, r)));

  if (!autoAllow) {
    const ok = await promptBash(ctx, cmd, r);
    if (!ok) return { block: true, reason: "User denied the command" };
  }

  // wrap in the sandbox (except in `off`)
  if (tier !== "off" && !cmd.trim().startsWith("bwrap")) {
    event.input.command = wrapInBwrap(cmd, ctx.cwd, tier);
  }
  return undefined;
}

async function handleNonBash(event: any, ctx: any) {
  // Auto-allow reads of files inside the project or allowed read dirs.
  if (isToolCallEventType("read", event)) {
    const target = await canonical(ctx.cwd, event.input.path);
    if (await isReadAllowed(ctx.cwd, target)) return undefined;
  }
  if (!ctx.hasUI) {
    return { block: true, reason: `Blocked: no UI to confirm tool "${event.toolName}"` };
  }
  let preview: string;
  try {
    preview = JSON.stringify(event.input);
  } catch {
    preview = String(event.input);
  }
  if (preview.length > 500) preview = preview.slice(0, 500) + "…";
  const choice = await ctx.ui.select(
    `Allow tool call?\n\nTool: ${event.toolName}\nInput: ${preview}`,
    ["Allow", "Disallow"],
  );
  if (choice !== "Allow") return { block: true, reason: `User denied tool "${event.toolName}"` };
  return undefined;
}

// ---------------------------------------------------------------------------
// extension entry
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  pi.registerCommand("guard", {
    description: "Set the safety tier: /guard off|on|net|readonly (no arg toggles off/on)",
    handler: async (args, ctx) => {
      const arg = args?.trim().toLowerCase();
      const tiers: Tier[] = ["off", "on", "net", "readonly"];
      let next: Tier | null = null;
      if (arg && tiers.includes(arg as Tier)) {
        next = arg as Tier;
      } else if (!arg) {
        next = tier === "off" ? "on" : "off";
      }
      if (next) {
        tier = next;
        ctx.ui.setStatus("guard", sandboxStatus());
        ctx.ui.notify(`Safety tier: ${tier}`, tier === "off" ? "warning" : "info");
      } else {
        ctx.ui.notify(`Unknown tier "${args}" — usage: /guard off|on|net|readonly`, "warning");
      }
    },
  });

  pi.on("session_start", (_event, ctx) => {
    ctx.ui.setStatus("guard", sandboxStatus());
  });

  pi.on("tool_call", async (event, ctx) => {
    ctx.ui.setStatus("guard", sandboxStatus());
    if (isToolCallEventType("bash", event)) return handleBash(event, ctx);
    return handleNonBash(event, ctx);
  });
}
