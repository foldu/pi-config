/**
 * Context cap: auto-compact at MAX_CONTEXT tokens, on any model.
 *
 * pi's built-in auto-compaction triggers at `contextWindow - reserveTokens`
 * (e.g. ~984k tokens on a 1M-window model like deepseek-v4-flash). Requests
 * beyond ~250k tokens get expensive on most providers, so this extension
 * triggers compaction as soon as the conversation reaches MAX_CONTEXT
 * instead — regardless of the model's reported window.
 *
 * Hooks `agent_settled`, which fires when the agent run is fully idle with
 * no automatic retry, compaction, or queued continuation pending. Triggering
 * `ctx.compact()` there never races the agent loop; pi serializes the
 * compaction before the next prompt. The built-in window threshold stays
 * enabled as a safety net for single turns that outgrow the window.
 *
 * After compaction, `getContextUsage()` reports `tokens: null` (unknown
 * until the next response), so this cannot re-trigger in a loop.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/** Compact once the conversation reaches this many tokens. */
const MAX_CONTEXT = 250_000;

export default function (pi: ExtensionAPI) {
  pi.on("agent_settled", (_event, ctx) => {
    const usage = ctx.getContextUsage();
    // tokens is null right after compaction / before the first response — skip.
    if (!usage || usage.tokens === null) return;
    if (usage.tokens < MAX_CONTEXT) return;

    ctx.ui.notify(
      `Context at ${usage.tokens.toLocaleString()} tokens — compacting (cap ${MAX_CONTEXT.toLocaleString()}).`,
      "info",
    );
    ctx.compact();
  });
}
