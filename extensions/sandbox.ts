/**
 * Sandbox Extension (scaffold)
 *
 * A very simplistic bubblewrap (bwrap) sandbox for the `bash` tool.
 *
 * - `/sandbox` toggles sandbox mode on/off (footer status shows while on).
 * - While on, every `bash` tool call is wrapped in a bwrap invocation with a
 *   read-only root, the project directory bound writable, a tmpfs /tmp, and
 *   no network.
 *
 * NOTE: This is a scaffold. It intentionally does NOT handle:
 *   - the read/write/edit tools (they still run outside the sandbox)
 *   - bwrap missing, or hosts without unprivileged user namespaces
 *   - escaping: a command already starting with `bwrap` is not re-wrapped
 */

import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

let sandboxEnabled = false;

/** Wrap a bash command in a bwrap invocation (project dir writable). */
function wrapInBwrap(command: string, cwd: string): string {
  const flags = [
    "--ro-bind",
    "/",
    "/", // read-only root
    "--bind",
    cwd,
    cwd, // project directory stays writable
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
    "--unshare-net", // no network
    "--unshare-pid",
    "--unshare-ipc",
    "--die-with-parent",
  ].join(" ");
  return `bwrap ${flags} bash -c ${JSON.stringify(command)}`;
}

export default function (pi: ExtensionAPI) {
  pi.registerCommand("sandbox", {
    description: "Toggle the bwrap sandbox for bash tool calls",
    handler: async (_args, ctx) => {
      sandboxEnabled = !sandboxEnabled;
      ctx.ui.notify(
        sandboxEnabled
          ? "Sandbox ON — bash tool calls are wrapped in bwrap"
          : "Sandbox OFF — bash runs normally",
        sandboxEnabled ? "warning" : "info",
      );
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    if (sandboxEnabled) {
      ctx.ui.setStatus("sandbox", "🛡 sandbox ON");
      if (isToolCallEventType("bash", event)) {
        const cmd = event.input.command;
        if (!cmd.trim().startsWith("bwrap")) {
          event.input.command = wrapInBwrap(cmd, ctx.cwd);
        }
      }
    } else {
      ctx.ui.setStatus("sandbox", undefined);
    }
    return undefined;
  });
}
