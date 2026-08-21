import { test } from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkRuntimeDeps, findBinary, installHint } from "../lib/environment.ts";

async function withTempDirs(
  spec: Array<[string, boolean]>, // [dirName, executable] relative to base
  fn: (base: string, pathEnv: string) => Promise<void>,
): Promise<void> {
  const base = join(tmpdir(), `guard-env-test-${process.pid}-${Math.random().toString(36).slice(2)}`);
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
    [["a", false], ["b", true]],
    async (base, pathEnv) => {
      const found = await findBinary("fake-bin", pathEnv);
      assert.equal(found, join(base, "b", "fake-bin"));
    },
  );
});

test("findBinary skips non-executable entries and empty/missing dirs", async () => {
  await withTempDirs(
    [["a", false], ["b", true]],
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
