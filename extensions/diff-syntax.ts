/**
 * Diff Syntax Highlighting Extension
 *
 * Overrides the built-in `edit` and `write` tools so their diffs are shown
 * with syntax highlighting, without duplicating the built-in rendering:
 *
 * - `edit`: the live diff preview shown by the built-in `renderCall` is
 *   re-rendered with syntax-highlighted code content. The built-in
 *   `renderResult` is kept, so the settled result diff is not duplicated.
 * - `write`: when writing to an EXISTING file, the old content is captured
 *   before execution and a diff (old → new) is rendered in the result slot
 *   with the +/- prefix and line numbers in the standard diff colors, and the
 *   code content highlighted by language. New files fall back to the built-in
 *   result rendering.
 *
 * Both diffs use pi's highlightCode + getLanguageFromPath. Per-line highlight
 * results are memoized (keyed by language + content + active theme) because
 * `renderCall`/`renderResult` re-run on every expand/resize/theme change, and
 * re-highlighting a large diff each frame causes visible stutter.
 *
 * Execution is fully delegated to the built-in tool definitions
 * (createEditToolDefinition / createWriteToolDefinition) — only rendering
 * changes.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Text } from "@earendil-works/pi-tui";
import {
  createEditToolDefinition,
  createWriteToolDefinition,
  generateDiffString,
  getLanguageFromPath,
  highlightCode,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI, Theme } from "@earendil-works/pi-coding-agent";

/** old content of existing files captured pre-execution, keyed by toolCallId */
const writeOldContent = new Map<string, string>();

/**
 * Symbol pi uses to share the active theme instance across module loaders
 * (see pi's theme.ts). Used as a cache key so syntax highlighting is
 * recomputed when the theme changes.
 */
const ACTIVE_THEME_SYMBOL = Symbol.for("@earendil-works/pi-coding-agent:theme");

interface CachedHighlight {
  theme: unknown;
  line: string;
}

type EditPreview = { diff: string; firstChangedLine: number | undefined } | { error: string };

/**
 * Per-line syntax highlight cache. renderResult re-runs on every
 * expand/resize/theme change; highlight.js is expensive enough that
 * re-highlighting a large diff every frame causes visible stutter.
 */
const highlightCache = new Map<string, CachedHighlight>();
const HIGHLIGHT_CACHE_MAX_ENTRIES = 2048;

function highlightLine(content: string, lang: string | undefined): string {
  if (!lang || !content) return content;
  const key = `${lang}\n${content}`;
  const activeTheme: unknown = Reflect.get(globalThis, ACTIVE_THEME_SYMBOL);
  const cached = highlightCache.get(key);
  if (cached && cached.theme === activeTheme) {
    return cached.line;
  }
  if (highlightCache.size >= HIGHLIGHT_CACHE_MAX_ENTRIES) {
    highlightCache.clear();
  }
  const highlighted = highlightCode(content, lang);
  const line = highlighted[0] ?? content;
  highlightCache.set(key, { theme: activeTheme, line });
  return line;
}

/**
 * Render a "+123 content" style diff string with diff-colored prefixes and
 * syntax-highlighted content. Mirrors pi's renderDiff line parsing.
 */
function renderHighlightedDiff(diffText: string, lang: string | undefined, theme: Theme): string {
  const out: string[] = [];
  for (const line of diffText.split("\n")) {
    const m = line.match(/^([+-\s])(\s*\d*)\s(.*)$/);
    if (!m) {
      out.push(theme.fg("toolDiffContext", line));
      continue;
    }
    const [, prefix, lineNum, content] = m;
    const colorKey =
      prefix === "-" ? "toolDiffRemoved" : prefix === "+" ? "toolDiffAdded" : "toolDiffContext";
    let body = content;
    if (lang && content) {
      body = highlightLine(content, lang);
    }
    out.push(theme.fg(colorKey, `${prefix}${lineNum} `) + body);
  }
  return out.join("\n");
}

function highlightedDiffComponent(
  diffText: string,
  lang: string | undefined,
  theme: Theme,
  context: any,
): Text {
  const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
  text.setText(renderHighlightedDiff(diffText, lang, theme));
  return text;
}

export default function (pi: ExtensionAPI) {
  const cwd = process.cwd();

  // ------------------------------------------------------------------
  // edit: syntax-highlight the built-in live diff preview
  // ------------------------------------------------------------------
  const editDef = createEditToolDefinition(cwd);
  const builtinEditRenderCall = editDef.renderCall;
  pi.registerTool({
    ...editDef,
    renderCall(args, theme, context) {
      const component = builtinEditRenderCall?.(args, theme, context);
      if (!component) return new Text("", 0, 0);
      const box = component as unknown as {
        preview?: EditPreview;
        children: Array<{ setText?: (text: string) => void }>;
      };
      const preview = box.preview;
      if (preview && !("error" in preview) && preview.diff) {
        const rawPath = String(
          (args as { file_path?: string; path?: string } | undefined)?.file_path ??
            (args as { file_path?: string; path?: string } | undefined)?.path ??
            "",
        );
        const lang = getLanguageFromPath(rawPath);
        // The built-in renderCall leaves the diff body as its last child (a
        // Text rendered with plain diff colors). Swap that content for the
        // syntax-highlighted version.
        const last = box.children[box.children.length - 1];
        if (last?.setText) {
          last.setText(renderHighlightedDiff(preview.diff, lang, theme));
        }
      }
      return component;
    },
  });

  // ------------------------------------------------------------------
  // write: capture old content pre-execution; diff when file exists
  // ------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    if (isToolCallEventType("write", event)) {
      // file_path is from an older pi schema; keep as a runtime fallback
      const input = event.input as { path: string; content: string; file_path?: string };
      const rawPath = String(input.file_path ?? input.path ?? "");
      try {
        writeOldContent.set(event.toolCallId, await readFile(resolve(ctx.cwd, rawPath), "utf8"));
      } catch {
        // file doesn't exist yet — new file, no diff
      }
    }
    return undefined;
  });

  const writeDef = createWriteToolDefinition(cwd);
  const builtinWriteRenderResult = writeDef.renderResult;
  pi.registerTool({
    ...writeDef,
    renderResult(result, options, theme, context) {
      const args = context.args as
        | { path?: string; file_path?: string; content?: string }
        | undefined;
      const rawPath = String(args?.file_path ?? args?.path ?? "");
      const lang = getLanguageFromPath(rawPath);
      // Compute the diff once and cache it in row state: renderResult re-runs
      // on every expand/resize/theme change, and the captured old content is
      // removed from the map after the first render.
      const state = context.state as { writeDiff?: string };
      if (state.writeDiff === undefined) {
        const old = writeOldContent.get(context.toolCallId);
        writeOldContent.delete(context.toolCallId);
        state.writeDiff =
          old !== undefined ? generateDiffString(old, String(args?.content ?? "")).diff : "";
      }
      if (state.writeDiff) {
        return highlightedDiffComponent(state.writeDiff, lang, theme, context);
      }
      return builtinWriteRenderResult?.(result, options, theme, context) ?? new Text("", 0, 0);
    },
  });
}
