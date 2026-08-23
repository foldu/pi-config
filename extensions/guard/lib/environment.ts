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

import { access, constants, stat } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface RuntimeDeps {
  /** Resolved absolute path, or null when missing from PATH. */
  bwrap: string | null;
  bash: string | null;
  socat: string | null;
}

export interface HiddenMount {
  kind: "tmpfs" | "null-bind";
  target: string;
}

/**
 * Classify config `hiddenPaths` for bwrap. Directories (and missing paths)
 * get an empty tmpfs mounted over them so their contents vanish; regular
 * files get /dev/null bound over them so reads return empty. bwrap can't
 * mount a tmpfs on top of a regular file, hence the split. Applied AFTER the
 * writableDirs binds (so they win over writable mounts) and BEFORE the ssh
 * agent bind (so the forwarded socket stays visible).
 */
/**
 * Classify config `hiddenPaths` for bwrap. Directories get an empty tmpfs
 * mounted over them so their contents vanish; regular files get /dev/null
 * bound over them so reads return empty. bwrap can't mount a tmpfs on top of
 * a regular file, hence the split.
 *
 * Missing paths: a name like `~/.ssh/id_` (CARE's SECRET_READ_PATHS prefix
 * form) isn't a real file — mounting over it would hide nothing. When `home`
 * is given, a missing path under it falls back to hiding the parent dir
 * (never HOME itself — that would wipe the project view — and never a system
 * dir, since hiding /etc would break the sandbox). Anything else gets an
 * empty tmpfs at the exact path, which is harmless when nothing exists there.
 *
 * Applied AFTER every other FS mount (/tmp, /var/tmp, writableDirs, the net
 * bridge) so nothing can shadow the hiding; loses only to the agent bind.
 */
export async function hiddenPathMounts(paths: string[], home?: string): Promise<HiddenMount[]> {
  const out: HiddenMount[] = [];
  const homePrefix = home ? `${home.replace(/\/+$/, "")}/` : null;
  for (const raw of paths) {
    const p = raw.replace(/\/+$/, "");
    try {
      const st = await stat(p);
      out.push(st.isDirectory() ? { kind: "tmpfs", target: p } : { kind: "null-bind", target: p });
    } catch {
      const parent = dirname(p);
      if (homePrefix && p.startsWith(homePrefix) && parent !== homePrefix.slice(0, -1)) {
        out.push({ kind: "tmpfs", target: parent }); // prefix → hide the dir
      } else {
        out.push({ kind: "tmpfs", target: p });
      }
    }
  }
  // The same target can resolve twice (e.g. ~/.ssh via both the "~/.ssh/id_"
  // prefix and "~/.ssh/authorized_keys") — collapse duplicates.
  const seen = new Set<string>();
  return out.filter((m) => {
    if (seen.has(m.target)) return false;
    seen.add(m.target);
    return true;
  });
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

// Environment whitelist for the sandbox. bwrap inherits the full host env by
// default, which would leak API keys/tokens into sandboxed commands — so the
// sandbox starts from `--clearenv` and gets back only this curated base plus
// the user's explicit `allowedEnv` config passthrough (secrets are opt-in).
const SANDBOX_ENV_BASE = [
  "HOME",
  "PATH",
  "TERM",
  "LANG",
  "LC_ALL",
  "TZ",
  "USER",
  "LOGNAME",
  "SHELL",
  "PWD",
];

/**
 * Build the sandbox environment as [key, value] pairs for `--setenv`.
 * `runtimeDir` (e.g. `/run/user/1000`) is re-exposed as XDG_RUNTIME_DIR so it
 * matches the private tmpfs the guard mounts there. `allowedEnv` is the
 * config escape hatch: entries are copied verbatim from the host env, so
 * secrets like CARGO_REGISTRY_TOKEN can be opted in explicitly. `sshAuthSock`
 * is the sandbox-side agent socket path (enabled via `/guard allow-ssh`);
 * when absent, SSH_AUTH_SOCK is stripped like every other secret.
 */
export function buildSandboxEnv(
  env: NodeJS.ProcessEnv,
  allowedEnv: string[],
  runtimeDir?: string,
  sshAuthSock?: string,
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const seen = new Set<string>();
  for (const key of SANDBOX_ENV_BASE) {
    const value = env[key];
    if (value === undefined || value === null) continue;
    out.push([key, value]);
    seen.add(key);
  }
  if (runtimeDir) {
    out.push(["XDG_RUNTIME_DIR", runtimeDir]);
    seen.add("XDG_RUNTIME_DIR");
  }
  if (sshAuthSock) {
    out.push(["SSH_AUTH_SOCK", sshAuthSock]);
    seen.add("SSH_AUTH_SOCK");
  }
  for (const key of allowedEnv) {
    if (seen.has(key)) continue;
    const value = env[key];
    if (value === undefined || value === null) continue;
    out.push([key, value]);
  }
  return out;
}
