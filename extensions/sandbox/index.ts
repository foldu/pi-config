/**
 * Sandbox Extension (scaffold)
 *
 * A very simplistic bubblewrap (bwrap) sandbox for the `bash` tool.
 *
 * - `/sandbox` toggles sandbox mode on/off (on by default; footer status
 *   shows while on).
 * - `/sandbox net` toggles network sandboxing (on by default). While ON,
 *   bash has no network (`--unshare-net`); while OFF, network is allowed.
 * - While sandbox is on, every `bash` tool call is wrapped in a bwrap
 *   invocation with:
 *     - read-only root (everything except the dirs below is read-only)
 *     - project dir + `WRITABLE_DIRS` bound writable (toolchain caches)
 *     - tmpfs /tmp and /var/tmp
 *     - no network (unless disabled), pid/ipc/uts namespaces, caps dropped
 *
 * Strictness notes:
 * - Sensitive dirs (~/.ssh, ~/.aws, ~/.gnupg, ...) are NOT in WRITABLE_DIRS,
 *   so they stay read-only inside the sandbox.
 * - Commands work because /nix/store, system profiles, and PATH are readable
 *   through the read-only root.
 * - Not implemented (future): env sanitization (env -i), seccomp, cgroup
 *   namespaces, --new-session.
 *
 * NOTE: This is a scaffold. It intentionally does NOT handle:
 *   - the read/write/edit tools (they still run outside the sandbox)
 *   - bwrap missing, or hosts without unprivileged user namespaces
 *   - escaping: a command already starting with `bwrap` is not re-wrapped
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { quote } from "shell-quote";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

let sandboxEnabled = true; // on by default
let netSandboxEnabled = true; // network sandboxing on by default

/** Expand a leading `~`/`~/` to the current user's home directory. */
function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p; // `~user/...` left as-is
}

/**
 * Directories bound WRITABLE inside the sandbox; everything else is
 * read-only. Toolchain caches (cargo, rustup, npm) and the project dir must
 * be writable for normal dev work. Missing dirs are skipped.
 *
 * Deliberately NOT included: ~/.ssh, ~/.aws, ~/.gnupg, ~/.password-store,
 * ~/.netrc, dotenv/secrets — they stay read-only.
 */
const WRITABLE_DIRS = [
  "~/.cargo",
  "~/.rustup",
  "~/.cache",
  "~/.local/share",
  "~/.config",
  "~/.npm",
];

/**
 * Wrap a bash command in a bwrap invocation.
 *
 * The whole invocation is assembled as argv and quoted with shell-quote, so
 * `cwd` (which may contain spaces) and the inner command (which may contain
 * quotes, `$(...)`, backticks, etc.) are passed through verbatim to the inner
 * `bash -c` without being interpreted by the outer shell.
 */
function wrapInBwrap(command: string, cwd: string, netSandbox: boolean): string {
  const args = [
    "bwrap",
    "--ro-bind", "/", "/", // read-only root (default-deny writes)
    "--bind", cwd, cwd, // project directory stays writable
  ];
  for (const dir of WRITABLE_DIRS) {
    const abs = expandHome(dir);
    if (existsSync(abs)) args.push("--bind", abs, abs);
  }
  args.push(
    "--dev", "/dev",
    "--proc", "/proc",
    "--tmpfs", "/tmp",
    "--tmpfs", "/var/tmp",
    ...(netSandbox ? ["--unshare-net"] : []), // no network when sandboxing net
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts", // fake hostname — no hostname reads/writes
    "--cap-drop", "ALL",
    "--die-with-parent",
    "bash", "-c", command,
  );
  return quote(args);
}

function sandboxStatus(): string {
  return sandboxEnabled
    ? netSandboxEnabled
      ? "🛡 sandbox ON · no net"
      : "🛡 sandbox ON · net allowed"
    : "";
}

export default function (pi: ExtensionAPI) {
  pi.registerCommand("sandbox", {
    description: "Toggle the bwrap sandbox; \"/sandbox net\" toggles network sandboxing",
    handler: async (args, ctx) => {
      const arg = args?.trim().toLowerCase();
      if (arg === "net") {
        netSandboxEnabled = !netSandboxEnabled;
        ctx.ui.notify(
          netSandboxEnabled
            ? "Network sandboxing ON — sandboxed bash has no network"
            : "Network sandboxing OFF — sandboxed bash may use the network",
          netSandboxEnabled ? "warning" : "info",
        );
        return;
      }
      if (arg) {
        ctx.ui.notify(`Unknown subcommand \"${args}\" — usage: /sandbox [net]`, "warning");
        return;
      }
      sandboxEnabled = !sandboxEnabled;
      ctx.ui.notify(
        sandboxEnabled
          ? `Sandbox ON — bash tool calls are wrapped in bwrap${netSandboxEnabled ? " (no network)" : " (network allowed)"}`
          : "Sandbox OFF — bash runs normally",
        sandboxEnabled ? "warning" : "info",
      );
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    if (sandboxEnabled) {
      ctx.ui.setStatus("sandbox", sandboxStatus());
      if (isToolCallEventType("bash", event)) {
        const cmd = event.input.command;
        if (!cmd.trim().startsWith("bwrap")) {
          event.input.command = wrapInBwrap(cmd, ctx.cwd, netSandboxEnabled);
        }
      }
    } else {
      ctx.ui.setStatus("sandbox", undefined);
    }
    return undefined;
  });
}
