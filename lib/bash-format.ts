/**
 * Shared bash-formatting helpers for pi extensions.
 *
 * Lives OUTSIDE the auto-discovered extensions dir so it is never loaded as
 * an extension itself; extensions import it via relative path.
 */

import { spawnSync } from "node:child_process";

let shfmtAvailable: boolean | undefined;

/** Probe once whether shfmt exists on PATH; cached for the session. */
export function isShfmtAvailable(): boolean {
  if (shfmtAvailable === undefined) {
    try {
      const r = spawnSync("shfmt", ["--version"], { encoding: "utf8", timeout: 5000 });
      shfmtAvailable = r.status === 0;
    } catch {
      shfmtAvailable = false;
    }
  }
  return shfmtAvailable;
}

/**
 * Format a bash command through shfmt for readability. Falls back to the
 * original command on any failure (shfmt missing, parse error, timeout).
 * shfmt is mostly behavior-preserving; see its docs for edge cases.
 */
export function formatBashCommand(command: string): string {
  if (!isShfmtAvailable()) return command;
  try {
    const result = spawnSync("shfmt", ["--language-dialect", "bash", "--simplify", "--binary-next-line"], {
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
