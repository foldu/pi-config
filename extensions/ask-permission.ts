/**
 * Ask Permission Extension
 *
 * Prompts for confirmation before every tool call.
 * - `read` tool calls for files inside the project directory or inside any
 *   directory in `ALLOWED_READ_DIRS` below are auto-allowed (no prompt).
 *   Reads elsewhere go through the dialog.
 * - `write` calls offer: Allow | Edit | Disallow.
 *   "Edit" opens the proposed content directly in your real external editor
 *   (`externalEditor` setting, `$VISUAL`, `$EDITOR`, or nano) — no in-TUI
 *   dialog. The edited content is what gets written. In headless/RPC mode it
 *   falls back to the built-in editor dialog.
 * - All other tools offer: Allow | Disallow.
 *
 * Blocks the tool call if the user disallows, or if there is no UI to ask with.
 */

import { resolve, relative, isAbsolute, sep, join } from "node:path";
import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { spawnSync } from "node:child_process";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/**
 * Directories whose files are auto-allowed for `read` (in addition to the
 * project directory). Entries support `~` (expanded to your home directory),
 * e.g. "~/.config". Add more as you like: "/tmp", a dotfiles repo, ...
 */
const ALLOWED_READ_DIRS = ["/nix", "~/.rustup", "~/.cargo"];

/**
 * Format a bash command through shfmt for readability. Falls back to the
 * original command on any failure (shfmt missing, parse error, timeout).
 * shfmt is mostly behavior-preserving; see its docs for edge cases.
 */
function formatBashCommand(command: string): string {
  try {
    const result = spawnSync("shfmt", ["-ln", "bash"], {
      input: command,
      encoding: "utf8",
      timeout: 5000,
    });
    if (result.status === 0 && typeof result.stdout === "string" && result.stdout.length > 0) {
      return result.stdout.replace(/\n$/, "");
    }
  } catch {
    // shfmt missing or failed — keep the original
  }
  return command;
}

/** True when `child` is `parent` itself or a path inside it (lexical). */
function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return (
    rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
  );
}

/** Resolve a path to an absolute, symlink-canonicalized path. */
async function canonical(base: string, p: string): Promise<string> {
  const abs = resolve(base, p);
  try {
    return await realpath(abs);
  } catch {
    return abs; // doesn't exist (yet) — fall back to the lexical path
  }
}

/** Expand a leading `~`/`~/` to the current user's home directory. */
function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p; // `~user/...` is left as-is (only the current user is resolvable here)
}

let allowedReadRoots: string[] | undefined;
async function getAllowedReadRoots(): Promise<string[]> {
  if (!allowedReadRoots) {
    allowedReadRoots = await Promise.all(
      ALLOWED_READ_DIRS.map((dir) => canonical(expandHome(dir), ".")),
    );
  }
  return allowedReadRoots;
}

/** True if `target` is inside the project dir or an allowed read dir. */
async function isReadAllowed(projectRoot: string, target: string): Promise<boolean> {
  if (isInside(await canonical(projectRoot, "."), target)) return true;
  for (const root of await getAllowedReadRoots()) {
    if (isInside(root, target)) return true;
  }
  return false;
}

export default function (pi: ExtensionAPI) {
  // Tools that never need confirmation. Add or remove as you like, e.g.:
  // const alwaysAllow = new Set(["web_search"]);
  const alwaysAllow = new Set<string>();

  pi.on("tool_call", async (event, ctx) => {
    if (alwaysAllow.has(event.toolName)) return undefined;


    // Auto-allow reads of files inside the project directory or allowed dirs.
    if (isToolCallEventType("read", event)) {
      const target = await canonical(ctx.cwd, event.input.path);
      if (await isReadAllowed(ctx.cwd, target)) return undefined;
    }

    if (!ctx.hasUI) {
      // Non-interactive modes (-p, --mode json/rpc): no UI to ask with — block by default
      return {
        block: true,
        reason: `Blocked: no UI to confirm tool "${event.toolName}"`,
      };
    }

    // Bash: show the script directly (shfmt-formatted for readability), never
    // the JSON wrapper, and never touch what actually executes.
    const isBash = isToolCallEventType("bash", event);
    let preview: string;
    if (isBash) {
      const cmd = event.input.command;
      preview = cmd.trim().startsWith("bwrap") ? cmd : formatBashCommand(cmd);
      if (preview.length > 2000) preview = preview.slice(0, 2000) + "\n…";
    } else {
      try {
        preview = JSON.stringify(event.input);
      } catch {
        preview = String(event.input);
      }
      if (preview.length > 500) preview = preview.slice(0, 500) + "…";
    }

    const options =  ["Allow", "Disallow"];
    const title = isBash
      ? `Allow bash?\n\n${preview}`
      : `Allow tool call?\n\nTool: ${event.toolName}\nInput: ${preview}`;

    const choice = await ctx.ui.select(title, options);

    if (choice !== "Allow") {
      return { block: true, reason: `User denied tool "${event.toolName}"` };
    }

    return undefined; // allow the call through
  });
}
