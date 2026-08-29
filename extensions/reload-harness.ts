/**
 * Reload Harness Extension
 *
 * Exposes an LLM-callable tool (`reload_harness`) that reloads the pi
 * runtime — extensions, skills, prompts, themes, and context files — the
 * same flow as the built-in `/reload` command.
 *
 * ## Why this exists: working on pi / pi extensions
 *
 * pi loads extensions at startup via jiti and keeps the loaded modules in
 * memory for the life of the process. Editing an extension (e.g. the guard,
 * this file itself) or pi's own code does NOT take effect in the running
 * session — the harness must be reloaded first. Before this extension, that
 * meant asking the human to type `/reload` or restart pi. With the tool, the
 * agent can reload on its own immediately after finishing an edit, then
 * verify the change in the same session. This is the extension you want
 * loaded while developing extensions: edit → reload → test, no human in the
 * loop.
 *
 * ## How it works
 *
 * Tools run with `ExtensionContext`, which has no `reload()` — only command
 * handlers get it. So the tool queues `/reload-harness` as a follow-up user
 * message (`pi.sendUserMessage(..., { deliverAs: "followUp" })`), and the
 * command handler then calls `ctx.reload()`. Reload emits `session_shutdown`
 * for the current extension runtime, reloads all resources, and re-emits
 * `session_start` with `reason: "reload"`.
 *
 * Treat reload as terminal for the handler: `await ctx.reload(); return;`.
 * Code after it runs in the pre-reload call frame, and in-memory state of
 * other extensions (guard's tier toggles, session-scoped dir lists) resets
 * to startup values — re-apply any runtime settings after reloading.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export default function (pi: ExtensionAPI) {
  // Command entrypoint for reload — tools can't call ctx.reload() directly.
  pi.registerCommand("reload-harness", {
    description: "Reload extensions, skills, prompts, themes, and context files",
    handler: async (_args, ctx) => {
      await ctx.reload();
    },
  });

  pi.registerTool({
    name: "reload_harness",
    label: "Reload Harness",
    description:
      "Reloads the pi harness — extensions, skills, prompts, themes, and context files (same as the /reload command). Use after editing extension code (extensions/*.ts or extensions/*/) or pi itself so the changes take effect in the running session.",
    promptSnippet: "Reload the pi harness after editing extension or pi code",
    promptGuidelines: [
      "Call this after editing an extension (e.g. extensions/guard) or pi itself — the harness keeps loaded modules in memory, so edits only apply after a reload.",
      "Reload resets session-scoped extension state (e.g. /guard tier toggles, add-dir lists) to startup defaults — re-apply runtime settings afterwards if needed.",
    ],
    parameters: Type.Object({}),
    async execute() {
      pi.sendUserMessage("/reload-harness", { deliverAs: "followUp" });
      return {
        content: [
          {
            type: "text",
            text: "Queued /reload-harness as a follow-up command — the harness will reload now.",
          },
        ],
        details: {},
      };
    },
  });
}
