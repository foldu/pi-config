import { test } from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSandboxEnv, checkRuntimeDeps, findBinary, installHint } from "../lib/environment.ts";

async function withTempDirs(
  spec: Array<[string, boolean]>, // [dirName, executable] relative to base
  fn: (base: string, pathEnv: string) => Promise<void>,
): Promise<void> {
  const base = join(
    tmpdir(),
    `guard-env-test-${process.pid}-${Math.random().toString(36).slice(2)}`,
  );
  await mkdir(base, { recursive: true });
  try {
    for (const [name, executable] of spec) {
      const dir = join(base, name);
      await mkdir(dir, { recursive: true });
      if (executable) {
        await writeFile(join(dir, "fake-bin"), "#!/bin/sh\nexit 0\n");
        await chmod(join(dir, "fake-bin"), 0o755);
      }
    }
    await fn(base, `${join(base, "a")}:${join(base, "b")}:${join(base, "missing")}:`);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

test("findBinary resolves an executable across colon-separated PATH entries", async () => {
  await withTempDirs(
    [
      ["a", false],
      ["b", true],
    ],
    async (base, pathEnv) => {
      const found = await findBinary("fake-bin", pathEnv);
      assert.equal(found, join(base, "b", "fake-bin"));
    },
  );
});

test("findBinary skips non-executable entries and empty/missing dirs", async () => {
  await withTempDirs(
    [
      ["a", false],
      ["b", true],
    ],
    async (base, pathEnv) => {
      // "a" has no fake-bin; "missing" doesn't exist; trailing ":" is empty.
      assert.equal(await findBinary("nonexistent-bin", pathEnv), null);
      // First executable match wins even when an earlier dir also has a file.
      const twoDirs = `${join(base, "a")}:${join(base, "b")}`;
      assert.equal(await findBinary("fake-bin", twoDirs), join(base, "b", "fake-bin"));
    },
  );
});

test("findBinary returns null for an empty PATH", async () => {
  assert.equal(await findBinary("fake-bin", ""), null);
  assert.equal(await findBinary("fake-bin", ":::"), null);
});

test("checkRuntimeDeps returns null-or-path for every binary", async () => {
  const deps = await checkRuntimeDeps(process.env.PATH ?? "");
  for (const key of ["bwrap", "bash", "socat"] as const) {
    assert.ok(
      deps[key] === null || typeof deps[key] === "string",
      `${key} should be null or a path, got ${deps[key]}`,
    );
  }
});

test("checkRuntimeDeps reports missing binaries against a bare PATH", async () => {
  await withTempDirs([], async (_base, pathEnv) => {
    const deps = await checkRuntimeDeps(pathEnv);
    assert.deepEqual(deps, { bwrap: null, bash: null, socat: null });
  });
});

test("installHint maps binary names to nix packages", () => {
  assert.equal(installHint("bwrap"), "nix profile install nixpkgs#bubblewrap");
  assert.equal(installHint("socat"), "nix profile install nixpkgs#socat");
  assert.equal(installHint("bash"), "nix profile install nixpkgs#bashInteractive");
});

test("buildSandboxEnv passes the base whitelist and drops secrets", () => {
  const env = {
    HOME: "/home/barnabas",
    PATH: "/usr/bin:/bin",
    TERM: "xterm-256color",
    LANG: "en_US.UTF-8",
    USER: "barnabas",
    // secrets must NOT leak into the sandbox
    DEEPSEEK_API_KEY: "sk-secret",
    GH_TOKEN: "ghp_secret",
    AWS_SECRET_ACCESS_KEY: "aws_secret",
    SSH_AUTH_SOCK: "/run/user/1000/ssh-agent.sock",
  };
  const out = buildSandboxEnv(env, [], "/run/user/1000");
  const keys = new Set(out.map(([k]) => k));
  for (const secret of ["DEEPSEEK_API_KEY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"]) {
    assert.ok(!keys.has(secret), `${secret} must be stripped`);
  }
  assert.equal(keys.has("HOME"), true);
  assert.deepEqual(out.find(([k]) => k === "XDG_RUNTIME_DIR")?.[1], "/run/user/1000");
});

test("buildSandboxEnv passes through allowedEnv (secrets opt-in)", () => {
  const env = { HOME: "/home/barnabas", CARGO_REGISTRY_TOKEN: "cargo_secret" };
  const out = buildSandboxEnv(env, ["CARGO_REGISTRY_TOKEN"], undefined);
  assert.deepEqual(out.find(([k]) => k === "CARGO_REGISTRY_TOKEN")?.[1], "cargo_secret");
});

test("buildSandboxEnv skips unset vars and dedupes against the base", () => {
  const env = { HOME: "/home/barnabas", PWD: "/work" };
  const out = buildSandboxEnv(env, ["HOME", "PWD"], undefined);
  // allowedEnv HOME/PWD already present via base — no duplicates
  assert.equal(out.filter(([k]) => k === "HOME").length, 1);
  assert.equal(out.filter(([k]) => k === "PWD").length, 1);
  assert.ok(!out.some(([k]) => k === "TERM")); // unset in env → skipped
});
