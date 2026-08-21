/**
 * The guard's binary closure. `package.json` covers the npm side; these are
 * the system binaries the sandbox/net features need at runtime:
 *
 *   - bwrap  — launches the sandbox (every tier except `off`)
 *   - bash   — runs the wrapped command inside the sandbox (`bwrap … bash -c`)
 *   - socat  — host-side + in-sandbox relays for the `on` tier's proxy egress
 *
 * Missing binaries are a *fail-closed* condition, never a silent bypass:
 * sandbox tiers refuse to run without bwrap/bash, and the `on` tier gets no
 * network egress without socat. Callers should surface `installHint()`.
 */

import { access, constants } from "node:fs/promises";
import { join } from "node:path";

export interface RuntimeDeps {
  /** Resolved absolute path, or null when missing from PATH. */
  bwrap: string | null;
  bash: string | null;
  socat: string | null;
}

/**
 * Resolve `name` to its executable path by scanning PATH (colon-separated).
 * Returns null when no PATH entry contains an executable `name`. Empty
 * entries and non-existent directories are skipped silently.
 */
export async function findBinary(name: string, pathEnv: string): Promise<string | null> {
  for (const entry of pathEnv.split(":")) {
    const dir = entry.trim();
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // not present or not executable — try the next PATH entry
    }
  }
  return null;
}

/** Check the full binary closure against the given PATH (default: process env). */
export async function checkRuntimeDeps(pathEnv = process.env.PATH ?? ""): Promise<RuntimeDeps> {
  const [bwrap, bash, socat] = await Promise.all([
    findBinary("bwrap", pathEnv),
    findBinary("bash", pathEnv),
    findBinary("socat", pathEnv),
  ]);
  return { bwrap, bash, socat };
}

/** Nix install hint for a missing binary (the user runs nix). */
export function installHint(binary: keyof RuntimeDeps): string {
  const pkg = binary === "bwrap" ? "bubblewrap" : binary === "socat" ? "socat" : "bashInteractive";
  return `nix profile install nixpkgs#${pkg}`;
}
