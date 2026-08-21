// Tests for the path-containment helpers behind read auto-allow.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { isInside, isReadAllowed } from "../lib/paths.ts";

describe("isInside", () => {
  it("is true for the parent itself", () => {
    assert.equal(isInside("/a/b", "/a/b"), true);
  });

  it("is true for a direct child", () => {
    assert.equal(isInside("/a/b", "/a/b/c"), true);
  });

  it("is true for a nested descendant", () => {
    assert.equal(isInside("/a/b", "/a/b/c/d.txt"), true);
  });

  it("is false for an ancestor", () => {
    assert.equal(isInside("/a/b", "/a"), false);
  });

  it("is false for the exact parent's parent (rel === '..')", () => {
    assert.equal(isInside("/a", "/a/.."), false);
  });

  it("is false for a sibling that shares a prefix", () => {
    assert.equal(isInside("/a/b", "/a/bc"), false);
    assert.equal(isInside("/a/b", "/a/bc/d"), false);
  });

  it("is false for an unrelated path", () => {
    assert.equal(isInside("/a/b", "/x/y"), false);
  });

  it("is false when escaping via ..", () => {
    assert.equal(isInside("/a/b", "/a/b/../c"), false);
  });

  it("treats the root as containing everything", () => {
    assert.equal(isInside("/", "/a"), true);
    assert.equal(isInside("/", "/a/b/c"), true);
  });
});

describe("isReadAllowed", () => {
  it("allows project + allowed roots, denies outside", async () => {
    const base = await mkdtemp(join(tmpdir(), "guard-paths-"));
    try {
      const project = join(base, "proj");
      const allowed = join(base, "allowed");
      await mkdir(join(project, "src"), { recursive: true });
      await mkdir(allowed, { recursive: true });

      assert.equal(await isReadAllowed(project, join(project, "src", "file.ts"), [allowed]), true);
      assert.equal(await isReadAllowed(project, join(project, "file.ts"), [allowed]), true);
      assert.equal(await isReadAllowed(project, join(allowed, "other.txt"), [allowed]), true);
      assert.equal(await isReadAllowed(project, join(base, "outside.txt"), [allowed]), false);
      assert.equal(await isReadAllowed(project, base, [allowed]), false); // ancestor
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });
});
