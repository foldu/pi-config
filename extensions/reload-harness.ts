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
 * handlers get it. So the tool dispatches the `/reload-harness` command
 * through `pi.sendUserMessage(..., { expandPromptTemplates: true })`:
 * extension commands run inline, even while the agent is streaming, so
 * `ctx.reload()` completes before this tool returns.
 *
 * `expandPromptTemplates` is load-bearing. Without it the text is queued as an
 * ordinary user message for the LLM, the command never executes, and the
 * reload silently doesn't happen (pi's own example in docs/extensions.md has
 * this bug).
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
      // Inline dispatch: extension commands are handled immediately, even
      // mid-stream, so the reload lands before this tool returns.
      await pi.sendUserMessage("/reload-harness", { expandPromptTemplates: true });
      return {
        content: [
          {
            type: "text",
            text: "Reloaded the harness — extensions, skills, prompts, themes, and context files.",
          },
        ],
        details: {},
      };
    },
  });
}
