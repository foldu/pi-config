/**
 * Unified guard extension.
 *
 * Merges the former ask-permission, sandbox, and CARE extensions into a single
 * `tool_call` handler so bash commands flow through one ordered pipeline:
 *
 *   1. CARE grades the command (ALLOW / WARN / DENY); DENY hard-blocks.
 *   2. The active safety tier decides auto-allow vs prompt vs block
 *      (see ./docs/safety-tiers.md).
 *   3. Approved commands are wrapped in the bwrap sandbox (unless tier is `off`).
 *
 * Non-bash tools keep the old ask-permission behavior: reads inside the project
 * (or the configured `allowedReadDirs`) auto-allow, everything else prompts.
 */

import { readFileSync } from "node:fs";
import { access as accessPath, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { quote } from "shell-quote";
import { parse as parseJsonc, type ParseError } from "jsonc-parser";
import { isToolCallEventType, createLocalBashOperations } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import {
  Text,
  type AutocompleteProvider,
  type AutocompleteSuggestions,
} from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { analyze } from "./lib/care/engine.ts";
import { resolve as resolveCare } from "./lib/care/resolution.ts";
import { SECRET_READ_PATHS } from "./lib/care/path.ts";
import { CLASS_MEANING } from "./lib/care/types.ts";
import { formatBashCommand } from "./lib/bash-format.ts";
import { guardAddDirCompletions, guardTierCompletions } from "./lib/guard-completions.ts";
import {
  checkRuntimeDeps,
  installHint,
  buildSandboxEnv,
  hiddenPathMounts,
} from "./lib/environment.ts";
import type { RuntimeDeps } from "./lib/environment.ts";
import { NetworkPolicy } from "./lib/egress/policy.ts";
import { startProxies } from "./lib/egress/proxy.ts";
import type { ProxyPair } from "./lib/egress/proxy.ts";
import {
  startBridge,
  stopBridge,
  buildNetEnvVars,
  buildSandboxNetCommand,
} from "./lib/egress/bridge.ts";
import type { NetBridge } from "./lib/egress/bridge.ts";
import type { AnalysisResult, Decision } from "./lib/care/types.ts";
import { canonical, isReadAllowed } from "./lib/paths.ts";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Tier = "off" | "on" | "net" | "isolated" | "readonly";

interface CareConfig {
  defaultTier: Tier;
  mode: "balanced" | "strict" | "auto";
  warnPolicy: "prompt" | "deny";
  allowedReadDirs: string[];
  writableDirs: string[];
  allowedHosts: string[];
  deniedHosts: string[];
  /** Env vars passed through to sandboxed commands (secrets are opt-in). */
  allowedEnv: string[];
  /** Per-class command overrides: { "WRITE_LOCAL": ["nix"] } reclassifies
   * the listed command heads (config wins over the built-in lexicon). Keys
   * must be valid RiskClass names; unknown keys are dropped with a warning.
   * Subcommand-aware heads (git, rm, chmod, dd, docker/podman, kill, sed -i)
   * keep their subcommand logic. */
  commandClasses: Record<string, string[]>;
  /** Paths (supports a leading ~) whose contents are hidden inside the
   * sandbox — stricter than read-only: directories become empty tmpfs, files
   * become /dev/null, so sandboxed commands can't read identity material
   * (ssh keys, agent sockets, cloud credentials) at all. */
  hiddenPaths: string[];
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
  allowedHosts: [],
  deniedHosts: [],
  allowedEnv: [],
  commandClasses: {},
  hiddenPaths: SECRET_READ_PATHS,
  overrides: { allowHeads: [], denyHeads: [], allowPaths: [], denyPaths: [] },
};

function loadConfig(): CareConfig {
  const path = join(homedir(), ".pi", "agent", "guard.jsonc");
  try {
    const text = readFileSync(path, "utf8");
    const errors: ParseError[] = [];
    const raw = parseJsonc(text, errors, { allowTrailingComma: true });
    if (errors.length > 0 || typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return DEFAULT_CONFIG;
    }
    return {
      ...DEFAULT_CONFIG,
      ...raw,
      commandClasses: sanitizeCommandClasses(raw.commandClasses),
      hiddenPaths: sanitizeHiddenPaths(raw.hiddenPaths),
      overrides: { ...DEFAULT_CONFIG.overrides, ...raw.overrides },
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

/** hiddenPaths is *additive*: the CARE SECRET_READ_PATHS prefill always stays,
 * and the config's own entries are appended (deduped). An empty `[]` in
 * guard.jsonc therefore means "just the prefill". */
function sanitizeHiddenPaths(raw: unknown): string[] {
  const extra = Array.isArray(raw) ? raw.filter((p): p is string => typeof p === "string") : [];
  return [...new Set([...SECRET_READ_PATHS, ...extra])];
}

/** Validate the config `commandClasses` record: keep valid RiskClass keys,
 * warn once about unknown keys or non-array values. */
function sanitizeCommandClasses(raw: unknown): Record<string, string[]> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const out: Record<string, string[]> = {};
  for (const [cls, progs] of Object.entries(raw)) {
    if (!Object.hasOwn(CLASS_MEANING, cls)) {
      console.warn(`guard: ignoring unknown command class "${cls}" in guard.jsonc commandClasses`);
      continue;
    }
    if (!Array.isArray(progs)) {
      console.warn(`guard: commandClasses["${cls}"] must be an array of command names — ignoring`);
      continue;
    }
    out[cls] = progs.filter((p): p is string => typeof p === "string");
  }
  return out;
}

const config = loadConfig();
let tier: Tier = config.defaultTier;
// SSH agent passthrough, toggled live via `/guard allow-ssh` (default off —
// fail closed). When on, the host agent socket is bound rw into the sandbox
// and SSH_AUTH_SOCK points at it; private keys never leave the host.
let sshForward = false;
// yolo mode, toggled live via `/guard yolo`: write/edit tool calls inside the
// project dir are auto-allowed without prompting — the same containment check
// reads already use. Approval-only: the sandbox, CARE, and bash prompting are
// untouched.
let yolo = false;
// Directories bound into the sandbox at runtime via `/guard add-dir`
// (read-only by default; `/guard add-dir <path> rw` binds writable — unless
// the readonly tier, which forces ro like everything else). Session-scoped
// like the tier: add to guard.jsonc `writableDirs` to persist.
const extraDirs: Array<{ path: string; writable: boolean }> = [];

// ---------------------------------------------------------------------------
// net whitelist (srt-style proxy egress for the `on` tier)
// ---------------------------------------------------------------------------

let netProxy: ProxyPair | null = null;
let netBridge: NetBridge | null = null;
let netPolicy: NetworkPolicy | null = null;
// Binary closure (bwrap/bash/socat), checked lazily once per process — see
// lib/environment.ts. Missing binaries fail closed, never bypass the sandbox.
let runtimeDeps: RuntimeDeps | null = null;
async function ensureRuntimeDeps(): Promise<RuntimeDeps> {
  runtimeDeps ??= await checkRuntimeDeps();
  return runtimeDeps;
}

/**
 * Mandatory closure check. Throwing here would just make pi disable the
 * guard (leaving the session unprotected), so a missing binary exits the
 * process with a clear message instead — pi must not run without its
 * enforcement tooling.
 */
async function assertRuntimeDeps(): Promise<void> {
  runtimeDeps = await checkRuntimeDeps();
  const missing: Array<[string, string]> = [];
  if (runtimeDeps.bwrap === null) missing.push(["bwrap", installHint("bwrap")]);
  if (runtimeDeps.socat === null) missing.push(["socat", installHint("socat")]);
  if (missing.length === 0) return;
  console.error(
    [
      "",
      "guard: mandatory runtime binaries are missing — refusing to start pi.",
      "The guard cannot provide containment or network enforcement without them.",
      "",
      ...missing.map(([name, hint]) => `  ${name} → ${hint}`),
      "",
      "Install them and restart pi (or remove the guard extension if you don't want it).",
      "",
    ].join("\n"),
  );
  process.exit(1);
}
let sessionUi: ExtensionUIContext | null = null;
// Sessions in this process using the guard; the net bridge/proxies are shared
// across them and torn down only when the last session closes.
let sessionCount = 0;

// The human's per-host verdicts, remembered for the session (so a command
// retrying a host doesn't re-prompt every request).
const hostDecisions = new Map<string, boolean>();
const inflightAsks = new Map<string, Promise<boolean>>();
let askQueue: Promise<unknown> = Promise.resolve();

async function doAskHost(host: string): Promise<boolean> {
  if (!sessionUi) return false; // fail closed (headless / before session_start)
  const choice = await sessionUi.select(
    `Network request from the sandbox\n\nHost: ${host}\n\nNot in allowedHosts — allow this host?`,
    ["Allow", "Deny"],
  );
  return choice === "Allow";
}

/** Prompt once per host, serialized + deduped; remember the verdict. */
function askHost(host: string): Promise<boolean> {
  const remembered = hostDecisions.get(host);
  if (remembered !== undefined) return Promise.resolve(remembered);
  const inFlight = inflightAsks.get(host);
  if (inFlight) return inFlight;
  const p = askQueue
    .then(() => doAskHost(host))
    .then(
      (allow) => {
        hostDecisions.set(host, allow);
        return allow;
      },
      () => false,
    )
    .finally(() => inflightAsks.delete(host));
  inflightAsks.set(host, p);
  return p;
}

function getNetPolicy(): NetworkPolicy | null {
  if (config.allowedHosts.length === 0) return null;
  if (!netPolicy) {
    netPolicy = new NetworkPolicy(config.allowedHosts, config.deniedHosts, askHost);
  }
  return netPolicy;
}

/** Lazily start the host proxies + socat bridges; null when not configured. */
async function ensureNetBridge(): Promise<NetBridge | null> {
  if (netBridge) return netBridge;
  const policy = getNetPolicy();
  if (!policy) return null;
  const deps = await ensureRuntimeDeps();
  if (deps.socat === null) return null; // fail closed: no egress, never bypass
  if (!netProxy) netProxy = await startProxies(policy);
  try {
    netBridge = await startBridge({ httpPort: netProxy.httpPort, socksPort: netProxy.socksPort });
  } catch {
    // socat present but the bridge failed (permissions, missing socket tools,
    // …) — fail closed: the sandbox stays unshared, so no egress.
    netProxy?.close();
    netProxy = null;
    return null;
  }
  return netBridge;
}

function stopNet(): void {
  void stopBridge(netBridge);
  netBridge = null;
  netProxy?.close();
  netProxy = null;
  netPolicy = null;
  hostDecisions.clear();
}

// ---------------------------------------------------------------------------
// bwrap sandbox
// ---------------------------------------------------------------------------

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p; // `~user/...` left as-is
}

/** PATH entries that live under $HOME (e.g. ~/.nix-profile/bin, ~/.local/bin,
 * ~/bin). These are ro-bound into the sandbox so the user's own installed
 * tools stay runnable — home itself is default-invisible, but whatever the
 * real PATH exposes from home must be reachable. Derived from the actual PATH
 * so the exposed set tracks what the user has installed, no config needed.
 * Entries equal to home itself are skipped (binding home ro would expose the
 * whole home through a PATH accident). */
function homePathDirs(pathEnv = process.env.PATH ?? ""): string[] {
  const home = homedir();
  const out = new Set<string>();
  for (const entry of pathEnv.split(":")) {
    if (!entry.startsWith("/")) continue; // relative PATH entries aren't dirs
    const p = entry.startsWith("~/") ? join(home, entry.slice(2)) : entry;
    if (p.startsWith(`${home}/`)) out.add(p);
  }
  return [...out];
}

/**
 * The current user's per-user runtime dir, e.g. `/run/user/1000`
 * (XDG_RUNTIME_DIR's standard location). Undefined when unknown (non-POSIX).
 */
function userRuntimeDir(): string | undefined {
  return typeof process.getuid === "function" ? `/run/user/${process.getuid()}` : undefined;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await accessPath(p);
    return true;
  } catch {
    return false;
  }
}

async function wrapInBwrap(command: string, cwd: string, t: Tier): Promise<string> {
  const deps = await ensureRuntimeDeps();
  if (deps.bwrap === null) {
    throw new Error(
      `guard: bwrap not found on PATH — cannot sandbox tier "${t}". Install with: ${installHint("bwrap")}`,
    );
  }
  if (deps.bash === null) {
    throw new Error(
      `guard: bash not found on PATH — cannot run commands inside the sandbox. Install with: ${installHint("bash")}`,
    );
  }
  // Whitelist root, NOT `--ro-bind / /`: the sandbox starts from an empty
  // tmpfs root and only the dirs below are bound in. Everything else on the
  // host — every other home dir, /root, /var, /opt, /srv, … — does not
  // exist inside the sandbox. A read-only root bind left all of it *visible*
  // (read-only, but readable: ~/.ssh, ~/.aws, cloud credentials, other
  // users' files). Default-deny visibility is the containment.
  // --ro-bind-try skips paths that don't exist (non-NixOS).
  const args: string[] = ["bwrap"];
  for (const p of [
    "/nix",
    "/run/current-system",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
  ]) {
    args.push("--ro-bind-try", p, p); // /etc: TLS certs, passwd, resolv.conf
  }
  // Empty, writable $HOME first (bwrap --dir creates parents): tools that
  // `cd ~` or write dotfiles (git, pip, node) keep working. Nothing of the
  // real home shows through it.
  args.push("--dir", homedir());
  for (const dir of homePathDirs()) {
    args.push("--ro-bind-try", dir, dir);
  }
  // SSH agent passthrough (`/guard allow-ssh`): bind the host agent socket rw
  // into the sandbox at a guard-owned path and point SSH_AUTH_SOCK at it.
  // The bind itself is appended AFTER the FS binds below — mount order
  // matters: `--bind ~/.cache ~/.cache` (writableDirs) would otherwise
  // remount over the socket and shadow it. A same-path bind would also be
  // shadowed by the private tmpfs at /run/user/<uid>, so we use
  // ~/.cache/guard/ssh-agent.sock with a pre-created placeholder file as the
  // bind target. Keys never leave the host.
  let sshAgentBind: [string, string] | null = null; // [hostSock, sandboxTarget]
  if (sshForward) {
    const hostSock = process.env.SSH_AUTH_SOCK;
    if (hostSock) {
      const target = join(homedir(), ".cache", "guard", "ssh-agent.sock");
      await mkdir(join(homedir(), ".cache", "guard"), { recursive: true });
      await writeFile(target, ""); // ensure the bind target exists as a regular file
      sshAgentBind = [hostSock, target];
    }
  }
  // Env sandboxing: bwrap inherits the host environment by default, which
  // would leak API keys/tokens into sandboxed commands. Start from
  // `--clearenv` and re-add a curated whitelist (base vars + the config's
  // explicit `allowedEnv` passthrough + XDG_RUNTIME_DIR matching the private
  // tmpfs mounted at /run/user/<uid>). The whitelist tier adds its proxy env
  // later, via buildNetEnvVars() below.
  args.push("--clearenv");
  for (const [key, value] of buildSandboxEnv(
    process.env,
    config.allowedEnv ?? [],
    userRuntimeDir(),
    sshAgentBind?.[1],
  )) {
    args.push("--setenv", key, value);
  }
  // Project + writable dirs (config `writableDirs` + runtime `/guard
  // add-dir` additions) are bound rw, or ro in the readonly tier. They used
  // to be visible via the ro root bind — with a whitelist root they must be
  // bound explicitly or they'd vanish entirely.
  const bindFlag = t === "readonly" ? "--ro-bind" : "--bind";
  args.push(bindFlag, cwd, cwd);
  for (const dir of config.writableDirs) {
    const abs = expandHome(dir);
    if (await pathExists(abs)) args.push(bindFlag, abs, abs);
  }
  // /guard add-dir dirs: per-dir writable flag (ro by default); the readonly
  // tier forces ro regardless, matching writableDirs.
  for (const d of extraDirs) {
    if (!(await pathExists(d.path))) continue;
    args.push(d.writable && t !== "readonly" ? "--bind" : "--ro-bind", d.path, d.path);
  }
  if (t !== "readonly") {
    // The user's runtime dir (/run/user/<uid>, XDG_RUNTIME_DIR) gets a
    // *private tmpfs*, not a host bind: tools that want a writable runtime
    // dir (podman's exit files, mktemp --tmpdir, …) get a fresh one, but the
    // host's agent/daemon sockets are deliberately NOT exposed — a rw bind
    // would hand the sandbox identity material (ssh-agent, gpg-agent, dbus)
    // and a container-daemon escape primitive (podman's rootless socket).
    // The uid is dynamic, so this can't live in guard.jsonc.
    const runtimeDir = userRuntimeDir();
    if (runtimeDir) args.push("--tmpfs", runtimeDir);
  }
  args.push(
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    // Bind the real /tmp + /var/tmp read-write instead of a fresh tmpfs per
    // command: tools stage state there (mktemp, test fixtures, editor locks,
    // pi's own temp files) and expect it to survive across calls. /tmp is
    // world-writable on Linux anyway; the sandbox still protects the rest of
    // the FS (default-deny root, cap-drop, no net unless `net` tier).
    "--bind",
    "/tmp",
    "/tmp",
    "--bind",
    "/var/tmp",
    "/var/tmp",
  );

  // `on` (the default): whitelisted network — zero interfaces, every
  // connection forced through the whitelist proxies; hosts not in the list
  // prompt the human. `isolated` / `readonly`: no network at all. `net`:
  // unrestricted host network (deliberate escape hatch, whitelist not
  // enforced).
  const whitelistMode = t === "on";
  const unshareNet = t !== "net"; // on, isolated, readonly

  if (whitelistMode) {
    const bridge = await ensureNetBridge();
    if (bridge) {
      // --bind (read-write): connect() on a Unix socket needs write access
      // to the socket inode, so a read-only bind would block all traffic.
      args.push("--bind", bridge.httpSocketPath, bridge.httpSocketPath);
      args.push("--bind", bridge.socksSocketPath, bridge.socksSocketPath);
      for (const [key, value] of buildNetEnvVars()) {
        args.push("--setenv", key, value);
      }
      command = buildSandboxNetCommand(command, bridge);
    }
    // bridge === null (socat/proxy failed): still unshare-net below, so the
    // sandbox has NO egress at all — fail closed, never bypass the whitelist.
  }

  // When the agent is forwarded (sshForward), sandboxed ssh needs ~/.ssh ro
  // (known_hosts, config, pubkeys) — under the old ro-root it was visible by
  // default; with a whitelist root it must be bound explicitly. The hidden
  // loop below skips the ~/.ssh hide in this mode.
  if (sshForward) {
    const sshDir = join(homedir(), ".ssh");
    if (await pathExists(sshDir)) args.push("--ro-bind", sshDir, sshDir);
  }
  // Hidden paths: contents made invisible to sandboxed commands (empty tmpfs
  // over dirs, /dev/null over files) — stricter than the whitelist root, for
  // identity material that shouldn't be readable at all (mostly system paths
  // like /etc/shadow now — home secrets are already invisible by default).
  // Mounted AFTER every other FS mount (/tmp, /var/tmp, /dev, /proc,
  // writableDirs, the net bridge): mounts apply in order, so this is the
  // only way they win over e.g. the real /tmp bind. They lose only to the
  // agent bind below, so the forwarded agent socket stays visible even if
  // ~/.cache/guard is hidden.
  //
  // When the agent is forwarded (sshForward), sandboxed ssh needs its config
  // to function — the prefilled ~/.ssh hide is skipped entirely, and ~/.ssh
  // is bound read-only just above (deliberately no writable bind: nothing
  // can write the real ~/.ssh, so host keys don't persist and accept-new
  // re-warns per host). The strict hide applies whenever the agent is NOT
  // forwarded.
  for (const m of await hiddenPathMounts(config.hiddenPaths.map(expandHome), homedir())) {
    if (sshForward && m.kind === "tmpfs" && m.target === join(homedir(), ".ssh")) continue;
    if (m.kind === "tmpfs") args.push("--tmpfs", m.target);
    else args.push("--bind", "/dev/null", m.target);
  }
  // The agent socket bind goes last of all: it must survive every other
  // mount (writableDirs, hidden paths) to keep the forwarded socket visible.
  // --dir creates the bind target's parent (usually ~/.cache/guard) in case
  // ~/.cache isn't a writableDir.
  if (sshAgentBind) {
    args.push("--dir", dirname(sshAgentBind[1]));
    args.push("--bind", sshAgentBind[0], sshAgentBind[1]);
  }

  if (unshareNet) args.push("--unshare-net");
  args.push(
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--cap-drop",
    "ALL",
    "--die-with-parent",
    "bash",
    "-c",
    command,
  );
  return quote(args);
}

// ssh-agent forwarding is only useful when the sandbox has direct network
// access. In `on` (proxy-only egress) / `isolated` / `readonly` plain ssh has
// no route out — warn loudly when that combo is active. `off` has no sandbox,
// so the host agent is naturally reachable (no mismatch).
function sshForwardMismatch(): boolean {
  return sshForward && tier !== "net" && tier !== "off";
}

function sandboxStatus(): string | undefined {
  const extras: string[] = [];
  if (sshForward) extras.push("ssh-agent");
  if (yolo) extras.push("yolo");
  const suffix = extras.length > 0 ? ` · ${extras.join(" · ")}` : "";
  let text: string | undefined;
  switch (tier) {
    case "off":
      // yolo is an approval-mode toggle, not containment, so it still shows
      // with the sandbox off (writes prompt only when yolo is off). No badge
      // otherwise, to keep the footer quiet in the common no-sandbox state.
      return yolo ? `🛡 guard OFF · yolo` : undefined;
    case "net":
      text = `🛡 guard ON · full net${suffix}`;
      break;
    case "isolated":
      text = `🛡 guard ON · no net${suffix}`;
      break;
    case "readonly":
      text = `🛡 guard ON · read-only${suffix}`;
      break;
    default:
      text = `🛡 guard ON · whitelist net${suffix}`;
  }
  // Red when ssh-agent is forwarded but the tier has no direct network: plain
  // ssh can't reach anything — the combo is almost certainly a mistake.
  // ANSI survives the footer's sanitizer (it only strips newlines/tabs) and
  // the TUI renders it (visibleWidth/extractAnsiCode are ANSI-aware).
  return sshForwardMismatch() ? `\x1b[31m${text}\x1b[0m` : text;
}

/**
 * Autocomplete for `/guard <tier>`: stack on the built-in provider, which
 * still handles `/command` completion itself. Delegate everything that isn't
 * a `/guard` line to the built-in (command names, file paths, …).
 */
function createGuardAutocompleteProvider(current: AutocompleteProvider): AutocompleteProvider {
  return {
    async getSuggestions(
      lines,
      cursorLine,
      cursorCol,
      options,
    ): Promise<AutocompleteSuggestions | null> {
      const beforeCursor = (lines[cursorLine] ?? "").slice(0, cursorCol);
      const completion = guardTierCompletions(beforeCursor);
      if (completion) {
        return { prefix: completion.prefix, items: completion.items };
      }
      const pathCompletion = await guardAddDirCompletions(beforeCursor);
      if (pathCompletion) {
        return { prefix: pathCompletion.prefix, items: pathCompletion.items };
      }
      return current.getSuggestions(lines, cursorLine, cursorCol, options);
    },
    applyCompletion(lines, cursorLine, cursorCol, item, prefix) {
      return current.applyCompletion(lines, cursorLine, cursorCol, item, prefix);
    },
    shouldTriggerFileCompletion(lines, cursorLine, cursorCol) {
      return current.shouldTriggerFileCompletion?.(lines, cursorLine, cursorCol) ?? true;
    },
  };
}

// ---------------------------------------------------------------------------
// read auto-allow (former ask-permission behavior)
// ---------------------------------------------------------------------------

let allowedReadRoots: string[] | undefined;
async function getAllowedReadRoots(): Promise<string[]> {
  if (!allowedReadRoots) {
    allowedReadRoots = await Promise.all(
      config.allowedReadDirs.map((dir) => canonical(expandHome(dir), ".")),
    );
  }
  return allowedReadRoots;
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

/** Human-readable one-line evidence for the dialog. */
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

function shortenCmd(cmd: string, max = 300): string {
  return cmd.length > max ? `${cmd.slice(0, max)}…` : cmd;
}

/**
 * LLM-readable block reason: states the command was NOT executed, which command,
 * why it is risky, why it became a hard block (score band vs. skip predicate),
 * and what to do.
 */
function explainBlock(
  cmd: string,
  r: AnalysisResult,
  f: { decision: Decision; skipReason: string | null },
): string {
  const cls = r.details.semanticMaxClass;
  const clsNote =
    cls && cls !== "READ_ONLY" && cls !== "UNKNOWN"
      ? `risk class "${cls.replace(/_/g, " ").toLowerCase()}" — ${CLASS_MEANING[cls]}`
      : null;
  const pathNote =
    r.details.path.reason && r.details.path.reason !== "paths_ok"
      ? `path issue: ${r.details.path.reason.replace(/_/g, " ")}`
      : null;
  const ruleNotes = r.firedRules
    .slice(0, 4)
    .map((rule) => `rule ${rule.ruleId} (${rule.description})`);
  const why =
    [clsNote, pathNote, ...ruleNotes].filter(Boolean).join("; ") || "no specific evidence";

  let escalation: string;
  if (f.skipReason === "p_spath") {
    escalation = "promoted to a hard block because it touches a protected or secret path";
  } else if (f.skipReason?.startsWith("p_sem")) {
    // skipReason is "p_sem:<CLASS>" — use the class it names, not semanticMaxClass
    const skipped = f.skipReason.slice("p_sem:".length).replace(/_/g, " ").toLowerCase();
    escalation = `promoted to a hard block because "${skipped}" is always blocked regardless of score`;
  } else if (f.skipReason?.startsWith("p_rule")) {
    escalation = `promoted to a hard block because it matches high-confidence MITRE-backed rule ${f.skipReason.slice("p_rule:".length)}`;
  } else if (f.decision === "DENY" && r.score >= 0.35) {
    escalation = "the score is above the hard-deny threshold";
  } else {
    escalation = "blocked by the current policy";
  }

  return [
    `CARE blocked: the command was NOT executed.`,
    `Blocked command: ${shortenCmd(cmd)}`,
    `Score: ${r.score.toFixed(2)} — ${escalation}.`,
    `Why: ${why}.`,
    "This is a hard block in every safety tier; retrying will not help. If the command is intentional and safe, ask the user to approve it or add an override in guard.jsonc.",
  ].join("\n");
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
  const r = analyze(cmd, { mode: config.mode, commandClasses: config.commandClasses });
  const f = resolveCare(r);
  let decision: Decision = f.decision;

  // overrides — deny wins over allow
  const head = rawHead(cmd);
  if (config.overrides.denyHeads.includes(head) || matchesPath(config.overrides.denyPaths, cmd)) {
    decision = "DENY";
  } else if (
    config.overrides.allowHeads.includes(head) ||
    matchesPath(config.overrides.allowPaths, cmd)
  ) {
    decision = "ALLOW";
  }

  // DENY — hard block in every tier
  if (decision === "DENY") {
    const viaOverride =
      config.overrides.denyHeads.includes(head) || matchesPath(config.overrides.denyPaths, cmd);
    const reason = viaOverride
      ? `CARE blocked: the command was NOT executed. Your guard override denies it (matches denyHeads/denyPaths). Blocked command: ${shortenCmd(cmd)}. Ask the user to adjust guard.jsonc if this was not intended.`
      : explainBlock(cmd, r, f);
    return { block: true, reason };
  }

  // readonly tier — write-context commands are blocked
  if (tier === "readonly" && !isPureRead(cmd, r)) {
    return {
      block: true,
      reason: `CARE blocked: the command was NOT executed. Tier is "readonly", which forbids writes. Blocked command: ${shortenCmd(cmd)}`,
    };
  }

  // warnPolicy deny — treat WARN like DENY
  if (decision === "WARN" && config.warnPolicy === "deny") {
    return {
      block: true,
      reason: `CARE blocked: the command was NOT executed. warnPolicy is "deny", so warnings are treated as blocks. ${explainBlock(cmd, r, f)}`,
    };
  }

  // auto-allow: only when contained (tier !== off), for ALLOW or clearly-read WARN
  const autoAllow =
    tier !== "off" && (decision === "ALLOW" || (decision === "WARN" && isReadOnlySafe(cmd, r)));

  if (!autoAllow) {
    const ok = await promptBash(ctx, cmd, r);
    if (!ok) return { block: true, reason: "User denied the command" };
  }

  // Approved — the custom bash tool wraps in the sandbox at execution time,
  // so the tool row shows the readable, un-wrapped command.
  return undefined;
}

async function handleNonBash(event: any, ctx: any) {
  // Auto-allow reads of files inside the project or allowed read dirs.
  if (isToolCallEventType("read", event)) {
    const target = await canonical(ctx.cwd, event.input.path);
    if (await isReadAllowed(ctx.cwd, target, await getAllowedReadRoots())) return undefined;
  }
  // yolo mode: write/edit tools get the same auto-allow as reads when their
  // target is inside the project (or the allowed read dirs). Approval-only —
  // the sandbox, CARE, and bash prompting are untouched.
  if (yolo && (isToolCallEventType("write", event) || isToolCallEventType("edit", event))) {
    const rawPath = String((event.input as { path?: string }).path ?? "");
    const target = await canonical(ctx.cwd, rawPath);
    if (await isReadAllowed(ctx.cwd, target, await getAllowedReadRoots())) return undefined;
  }
  if (!ctx.hasUI) {
    return { block: true, reason: `Blocked: no UI to confirm tool "${event.toolName}"` };
  }

  // read/write/edit show only the file path (resolved); other tools show the JSON.
  const fileAction: Record<string, string> = {
    read: "reading",
    write: "writing",
    edit: "editing",
  };
  const action = fileAction[event.toolName];
  let title: string;
  if (action) {
    const rawPath = String((event.input as { path?: string }).path ?? "");
    const resolved = await canonical(ctx.cwd, rawPath);
    title = `Allow ${action} this file?\n\n${resolved}`;
  } else {
    let preview: string;
    try {
      preview = JSON.stringify(event.input, null, 2);
    } catch {
      preview = String(event.input);
    }
    if (preview.length > 1000) preview = preview.slice(0, 1000) + "\n…";
    title = `Allow tool call?\n\nTool: ${event.toolName}\nInput:\n${preview}`;
  }

  const choice = await ctx.ui.select(title, ["Allow", "Disallow"]);
  if (choice !== "Allow") return { block: true, reason: `User denied tool "${event.toolName}"` };
  return undefined;
}

// ---------------------------------------------------------------------------
// extension entry
// ---------------------------------------------------------------------------

const MAX_BYTES = 50 * 1024;

const bashSchema = Type.Object({
  command: Type.String({ description: "Bash command to execute" }),
  timeout: Type.Optional(
    Type.Number({ description: "Timeout in seconds (optional, no default timeout)" }),
  ),
});

function appendStatus(text: string, status: string): string {
  return `${text ? `${text}\n\n` : ""}${status}`;
}

export default async function (pi: ExtensionAPI) {
  await assertRuntimeDeps(); // mandatory: exits pi when bwrap/socat are missing
  pi.registerCommand("guard", {
    description:
      "Set the safety tier: /guard off|on|net|isolated|readonly (no arg toggles off/on). /guard allow-ssh [on|off] forwards the host ssh-agent into the sandbox. /guard yolo [on|off] auto-allows writes/edits in the project dir. /guard add-dir <path> [rw] binds an extra dir into the sandbox for the session (ro, rw optional).",
    handler: async (args, ctx) => {
      const [cmdRaw, ...rest] = (args ?? "").trim().split(/\s+/);
      const cmd = (cmdRaw ?? "").toLowerCase(); // keep rest at original case — paths are case-sensitive
      if (cmd === "allow-ssh") {
        const sub = rest[0];
        if (sub !== undefined && sub !== "on" && sub !== "off") {
          ctx.ui.notify("usage: /guard allow-ssh [on|off]", "warning");
          return;
        }
        const enable = sub === undefined ? !sshForward : sub === "on";
        if (enable && !process.env.SSH_AUTH_SOCK) {
          ctx.ui.notify("allow-ssh: no SSH_AUTH_SOCK on the host — nothing to forward", "warning");
          return;
        }
        sshForward = enable;
        ctx.ui.setStatus("guard", sandboxStatus());
        ctx.ui.notify(
          enable ? "ssh-agent forwarded into the sandbox" : "ssh-agent forwarding off",
          "info",
        );
        if (enable && sshForwardMismatch()) {
          ctx.ui.notify(
            "allow-ssh: this tier has no direct network (plain ssh cannot reach hosts) — switch to /guard net",
            "warning",
          );
        }
        return;
      }
      if (cmd === "yolo") {
        const sub = rest[0];
        if (sub !== undefined && sub !== "on" && sub !== "off") {
          ctx.ui.notify("usage: /guard yolo [on|off]", "warning");
          return;
        }
        const enable = sub === undefined ? !yolo : sub === "on";
        yolo = enable;
        ctx.ui.setStatus("guard", sandboxStatus());
        ctx.ui.notify(
          enable
            ? "yolo: writes/edits inside the project dir are auto-allowed (no prompt); DENY and bash prompting still apply"
            : "yolo off: writes/edits prompt again",
          enable ? "warning" : "info",
        );
        return;
      }
      if (cmd === "add-dir") {
        // optional trailing `rw`/`ro` flag; the rest (joined) is the path
        let writable = false;
        let dir = rest.join(" ").trim();
        const last = rest[rest.length - 1];
        if (last === "rw" || last === "ro") {
          writable = last === "rw";
          dir = rest.slice(0, -1).join(" ").trim();
        }
        if (!dir) {
          ctx.ui.notify(
            "usage: /guard add-dir <path> [rw] — bind a dir into the sandbox (ro by default, rw optional)",
            "warning",
          );
          return;
        }
        const abs = resolve(ctx.cwd, expandHome(dir));
        if (!(await pathExists(abs))) {
          ctx.ui.notify(`add-dir: ${abs} does not exist`, "warning");
          return;
        }
        const existing = extraDirs.find((d) => d.path === abs);
        if (existing) {
          if (existing.writable !== writable) {
            existing.writable = writable;
            ctx.ui.notify(
              `add-dir: ${abs} now ${writable ? "writable" : "read-only"} in the sandbox`,
              "info",
            );
          } else {
            ctx.ui.notify(
              `add-dir: ${abs} is already in the sandbox (${writable ? "writable" : "read-only"})`,
              "info",
            );
          }
          return;
        }
        if (config.writableDirs.some((d) => expandHome(d) === abs)) {
          ctx.ui.notify(`add-dir: ${abs} is already in the sandbox (writable via config)`, "info");
          return;
        }
        const effective = writable && tier !== "readonly";
        extraDirs.push({ path: abs, writable });
        ctx.ui.notify(
          `add-dir: ${abs} bound ${effective ? "writable" : "read-only"}${
            tier === "readonly"
              ? " (readonly tier forces ro)"
              : " — this session only; add to guard.jsonc writableDirs to persist"
          }`,
          "info",
        );
        return;
      }
      const tiers: Tier[] = ["off", "on", "net", "isolated", "readonly"];
      let next: Tier | null = null;
      if (cmd && tiers.includes(cmd as Tier)) {
        next = cmd as Tier;
      } else if (!cmd) {
        next = tier === "off" ? "on" : "off";
      }
      if (next) {
        tier = next;
        if (tier === "off") await stopNet(); // free the proxies/bridges
        ctx.ui.setStatus("guard", sandboxStatus());
        ctx.ui.notify(`Safety tier: ${tier}`, tier === "off" ? "warning" : "info");
        if (sshForward && sshForwardMismatch()) {
          ctx.ui.notify(
            "ssh-agent forwarding is on, but this tier has no direct network (plain ssh cannot reach hosts) — use /guard net",
            "warning",
          );
        }
      } else {
        ctx.ui.notify(
          `Unknown "${cmd}" — usage: /guard off|on|net|isolated|readonly | allow-ssh [on|off] | yolo [on|off] | add-dir <path> [rw]`,
          "warning",
        );
      }
    },
  });

  pi.registerTool({
    name: "bash", // overrides the built-in bash tool
    label: "bash",
    description:
      "Execute a bash command in the current working directory. Returns stdout and stderr. Output is truncated to last 50KB. Optionally provide a timeout in seconds.",
    promptSnippet: "Execute bash commands (ls, grep, find, etc.)",
    promptGuidelines: [
      "You can inspect PI_* environment variables for current model and session details.",
    ],
    parameters: bashSchema,

    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      // Wrap in the sandbox at execution time (tier != off). The command shown
      // in the tool row stays the readable original.
      let command = params.command;
      if (tier !== "off" && !command.trim().startsWith("bwrap")) {
        command = await wrapInBwrap(command, ctx.cwd, tier);
      }
      const ops = createLocalBashOperations();
      let output = "";
      const onData = (data: Buffer) => {
        output += data.toString();
      };

      let exitCode: number | null = null;
      try {
        ({ exitCode } = await ops.exec(command, ctx.cwd, {
          onData,
          signal,
          timeout: params.timeout,
        }));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message === "aborted") {
          throw new Error(appendStatus(output, "Command aborted"));
        }
        if (message.startsWith("timeout:")) {
          const seconds = message.split(":")[1];
          throw new Error(appendStatus(output, `Command timed out after ${seconds} seconds`));
        }
        throw err;
      }

      let text = output;
      if (Buffer.byteLength(text, "utf8") > MAX_BYTES) {
        text = text.slice(-MAX_BYTES) + "\n\n[Output truncated at 50KB]";
      }
      if (text.length === 0) text = "(no output)";
      if (exitCode !== 0 && exitCode !== null) {
        throw new Error(appendStatus(text, `Command exited with code ${exitCode}`));
      }
      return { content: [{ type: "text", text }], details: undefined };
    },

    // Show the shfmt-formatted original command in the tool row; the sandbox
    // wrapping happens inside execute (see above), so this stays readable.
    renderCall(args, theme, context) {
      const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
      const formatted = formatBashCommand(args.command);
      const timeoutSuffix = args.timeout ? theme.fg("muted", ` (timeout ${args.timeout}s)`) : "";
      text.setText(theme.fg("toolTitle", theme.bold(`$ ${formatted}`)) + timeoutSuffix);
      return text;
    },
    // renderResult omitted → built-in bash result rendering is inherited
  });

  pi.on("session_start", (_event, ctx) => {
    sessionCount++;
    sessionUi = ctx.ui;
    ctx.ui.setStatus("guard", sandboxStatus());
    ctx.ui.addAutocompleteProvider((current) => createGuardAutocompleteProvider(current));
  });

  pi.on("session_shutdown", () => {
    // Sessions share the net bridge/proxies; only tear them down when the
    // last session in this process closes (other sessions may still use them).
    sessionCount = Math.max(0, sessionCount - 1);
    if (sessionCount === 0) stopNet();
  });

  pi.on("tool_call", async (event, ctx) => {
    ctx.ui.setStatus("guard", sandboxStatus());
    if (isToolCallEventType("bash", event)) return handleBash(event, ctx);
    return handleNonBash(event, ctx);
  });
}
