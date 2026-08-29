import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
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
  {
    value: "yolo",
    label: "yolo",
    description: "auto-allow write/edit tools inside the project dir (on/off)",
  },
  {
    value: "add-dir",
    label: "add-dir",
    description: "bind an extra writable dir into the sandbox for the session (path)",
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

// `/guard add-dir <path>` — the path token follows the subcommand; the space
// is required so bare `add-dir` (subcommand completion, no path yet) and
// `add-dir ` (empty token → list cwd) are distinct.
const GUARD_ADD_DIR_RE = /^\/guard[ \t]+add-dir[ \t]+(\S*)$/i;

/**
 * Path completions for `/guard add-dir <path>`: read the partial's parent
 * dir and suggest matching entries (dirs get a trailing slash so Tab keeps
 * descending). Relative partials resolve against process.cwd(), `~/` against
 * $HOME; completed values keep the `~` form for home paths, else absolute —
 * both accepted by add-dir. Returns null when the line isn't an add-dir
 * invocation, the dir can't be read, or nothing matches, so the caller can
 * delegate to the built-in provider.
 */
export async function guardAddDirCompletions(
  beforeCursor: string,
): Promise<{ prefix: string; items: AutocompleteItem[] } | null> {
  const match = GUARD_ADD_DIR_RE.exec(beforeCursor);
  if (!match) return null;
  const partial = match[1] ?? "";
  const tilde = partial.startsWith("~/");
  const abs = tilde ? join(homedir(), partial.slice(2)) : partial;
  const lastSlash = abs.lastIndexOf("/");
  const dirPart = lastSlash >= 0 ? abs.slice(0, lastSlash + 1) : "";
  const namePrefix = lastSlash >= 0 ? abs.slice(lastSlash + 1) : abs;
  const base = dirPart === "" ? process.cwd() : dirPart.replace(/\/+$/, "") || "/";
  let entries;
  try {
    entries = await readdir(base, { withFileTypes: true });
  } catch {
    return null; // unreadable/missing parent dir — nothing to suggest
  }
  const home = homedir();
  const items: AutocompleteItem[] = [];
  for (const e of entries) {
    if (!e.name.startsWith(namePrefix)) continue;
    const isDir = e.isDirectory();
    const full = join(base, e.name) + (isDir ? "/" : "");
    items.push({
      // keep the `~/` form for home paths (matches how the user typed it)
      value: tilde && full.startsWith(`${home}/`) ? join("~", full.slice(home.length)) : full,
      label: e.name + (isDir ? "/" : ""),
      description: full,
    });
  }
  if (items.length === 0) return null;
  items.sort((a, b) => {
    const ad = a.label.endsWith("/");
    const bd = b.label.endsWith("/");
    return ad === bd ? a.label.localeCompare(b.label) : ad ? -1 : 1; // dirs first
  });
  return { prefix: partial, items };
}
