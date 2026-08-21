// Path-containment helpers for the guard's read auto-allow.
import { resolve, relative, isAbsolute, sep } from "node:path";
import { realpath } from "node:fs/promises";

/** True when `child` is `parent` itself or a path inside it (lexical). */
export function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** Resolve to an absolute, symlink-canonicalized path (lexical fallback). */
export async function canonical(base: string, p: string): Promise<string> {
  const abs = resolve(base, p);
  try {
    return await realpath(abs);
  } catch {
    return abs; // doesn't exist (yet) — fall back to the lexical path
  }
}

/**
 * True if `target` is inside the project dir or any allowed root.
 * `target` and `allowedRoots` should already be absolute (canonicalized);
 * `projectRoot` is canonicalized here.
 */
export async function isReadAllowed(
  projectRoot: string,
  target: string,
  allowedRoots: string[],
): Promise<boolean> {
  if (isInside(await canonical(projectRoot, "."), target)) return true;
  for (const root of allowedRoots) {
    if (isInside(root, target)) return true;
  }
  return false;
}
