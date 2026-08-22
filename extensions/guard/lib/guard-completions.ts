import type { AutocompleteItem } from "@earendil-works/pi-tui";

/** Tier suggestions for `/guard <partial>` — order mirrors the docs. */
export const GUARD_TIER_ITEMS: AutocompleteItem[] = [
  {
    value: "off",
    label: "off",
    description: "no sandbox — everything prompts (CARE DENY still blocks)",
  },
  {
    value: "on",
    label: "on",
    description: "default — whitelisted net, new hosts prompt",
  },
  {
    value: "net",
    label: "net",
    description: "full host network (escape hatch)",
  },
  {
    value: "isolated",
    label: "isolated",
    description: "no network at all",
  },
  {
    value: "readonly",
    label: "readonly",
    description: "read-only FS — writes blocked before running",
  },
  {
    value: "allow-ssh",
    label: "allow-ssh",
    description: "forward the host ssh-agent into the sandbox (on/off)",
  },
];

// `/guard` optionally followed by whitespace + a partial argument (letters or
// hyphens, for allow-ssh), anchored at line start (like real slash commands).
// `/guardx` or `foo /guard on` don't match.
const GUARD_ARG_RE = /^\/guard(?:[ \t]+([a-z-]*))?$/i;

/**
 * Returns tier completions for the text before the cursor, or null when the
 * line is not a `/guard` invocation (the caller should delegate to the
 * built-in provider). `prefix` is the partial argument, so applying a
 * completion replaces only the argument and leaves `/guard ` intact.
 */
export function guardTierCompletions(
  beforeCursor: string,
): { prefix: string; items: AutocompleteItem[] } | null {
  const match = GUARD_ARG_RE.exec(beforeCursor);
  if (!match) return null;
  const partial = (match[1] ?? "").toLowerCase();
  const items = GUARD_TIER_ITEMS.filter((t) => t.value.startsWith(partial));
  if (items.length === 0) return null;
  return { prefix: partial, items };
}
