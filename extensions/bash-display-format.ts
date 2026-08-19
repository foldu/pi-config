/**
 * Bash Display Format Extension
 *
 * Overrides the built-in `bash` tool so that:
 * - the command shown in the TUI tool row is formatted through shfmt for
 *   readability, and
 * - the command that actually executes is the ORIGINAL, unformatted one.
 *
 * Execution uses pi's own local shell backend (`createLocalBashOperations`),
 * so spawning, cwd checks, timeouts, and abort handling match the built-in.
 * Result rendering is inherited from the built-in bash renderer (omitting
 * `renderResult`); only the tool-call header is customized.
 *
 * Caveats vs. the built-in tool (simplified on purpose):
 * - no streaming progress updates (results appear when the command finishes)
 * - output capped at 50KB with a truncation note (no full-output temp file)
 * - PI_* session env vars are not injected
 */

import { spawnSync } from "node:child_process";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { createLocalBashOperations } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const MAX_BYTES = 50 * 1024;

const bashSchema = Type.Object({
  command: Type.String({ description: "Bash command to execute" }),
  timeout: Type.Optional(Type.Number({ description: "Timeout in seconds (optional, no default timeout)" })),
});

/** Format a bash command through shfmt for display. Falls back to original. */
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

function appendStatus(text: string, status: string): string {
  return `${text ? `${text}\n\n` : ""}${status}`;
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "bash", // overrides the built-in bash tool
    label: "bash",
    description:
      "Execute a bash command in the current working directory. Returns stdout and stderr. Output is truncated to last 50KB. Optionally provide a timeout in seconds.",
    // promptSnippet/promptGuidelines are not inherited from the built-in tool
    promptSnippet: "Execute bash commands (ls, grep, find, etc.)",
    promptGuidelines: ["You can inspect PI_* environment variables for current model and session details."],
    parameters: bashSchema,

    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const ops = createLocalBashOperations();
      let output = "";
      const onData = (data: Buffer) => {
        output += data.toString();
      };

      let exitCode: number | null = null;
      try {
        ({ exitCode } = await ops.exec(params.command, ctx.cwd, {
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

    // Show the shfmt-formatted command in the tool row; execution uses the
    // original params.command (see execute above).
    renderCall(args, theme, context) {
      const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
      const formatted = formatBashCommand(args.command);
      const timeoutSuffix = args.timeout ? theme.fg("muted", ` (timeout ${args.timeout}s)`) : "";
      text.setText(theme.fg("toolTitle", theme.bold(`$ ${formatted}`)) + timeoutSuffix);
      return text;
    },
    // renderResult omitted → built-in bash result rendering is inherited
    // (colored output, duration, truncation warnings).
  });
}
