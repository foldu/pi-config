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
 *   invocation with a read-only root, the project directory bound writable,
 *   a tmpfs /tmp, and (unless disabled) no network.
 *
 * NOTE: This is a scaffold. It intentionally does NOT handle:
 *   - the read/write/edit tools (they still run outside the sandbox)
 *   - bwrap missing, or hosts without unprivileged user namespaces
 *   - escaping: a command already starting with `bwrap` is not re-wrapped
 */

import { quote } from "shell-quote";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

let sandboxEnabled = true; // on by default
let netSandboxEnabled = true; // network sandboxing on by default

/**
 * Wrap a bash command in a bwrap invocation (project dir writable).
 *
 * The whole invocation is assembled as argv and quoted with shell-quote, so
 * `cwd` (which may contain spaces) and the inner command (which may contain
 * quotes, `$(...)`, backticks, etc.) are passed through verbatim to the inner
 * `bash -c` without being interpreted by the outer shell.
 */
function wrapInBwrap(command: string, cwd: string, netSandbox: boolean): string {
  const args = [
    "bwrap",
    "--ro-bind", "/", "/", // read-only root
    "--bind", cwd, cwd, // project directory stays writable
    "--dev", "/dev",
    "--proc", "/proc",
    "--tmpfs", "/tmp",
    ...(netSandbox ? ["--unshare-net"] : []), // no network when sandboxing net
    "--unshare-pid",
    "--unshare-ipc",
    "--die-with-parent",
    "bash", "-c", command,
  ];
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
