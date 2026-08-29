import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  guardAddDirCompletions,
  guardTierCompletions,
  GUARD_TIER_ITEMS,
} from "../lib/guard-completions.ts";

test("bare `/guard` offers all subcommands with an empty prefix", () => {
  const r = guardTierCompletions("/guard");
  assert.ok(r);
  assert.equal(r.prefix, "");
  assert.deepEqual(
    r.items.map((i) => i.value),
    ["off", "on", "net", "isolated", "readonly", "allow-ssh", "yolo", "add-dir"],
  );
});

test("`/guard ` (trailing space) also offers all tiers", () => {
  const r = guardTierCompletions("/guard ");
  assert.ok(r);
  assert.equal(r.prefix, "");
  assert.equal(r.items.length, GUARD_TIER_ITEMS.length);
});

test("partial argument filters and is reported as the prefix", () => {
  const r = guardTierCompletions("/guard o");
  assert.ok(r);
  assert.equal(r.prefix, "o");
  assert.deepEqual(
    r.items.map((i) => i.value),
    ["off", "on"],
  );
  assert.deepEqual(
    guardTierCompletions("/guard is")!.items.map((i) => i.value),
    ["isolated"],
  );
  assert.deepEqual(
    guardTierCompletions("/guard net")!.items.map((i) => i.value),
    ["net"],
  );
});

test("case-insensitive argument matching", () => {
  assert.deepEqual(
    guardTierCompletions("/guard OFF")!.items.map((i) => i.value),
    ["off"],
  );
});

test("yolo completes", () => {
  assert.deepEqual(
    guardTierCompletions("/guard y")!.items.map((i) => i.value),
    ["yolo"],
  );
  assert.deepEqual(
    guardTierCompletions("/guard yol")!.items.map((i) => i.value),
    ["yolo"],
  );
  assert.deepEqual(
    guardTierCompletions("/guard yolo")!.items.map((i) => i.value),
    ["yolo"],
  );
});

test("allow-ssh completes through the hyphen", () => {
  assert.deepEqual(
    guardTierCompletions("/guard allow")!.items.map((i) => i.value),
    ["allow-ssh"],
  );
  assert.deepEqual(
    guardTierCompletions("/guard allow-s")!.items.map((i) => i.value),
    ["allow-ssh"],
  );
  assert.equal(guardTierCompletions("/guard allow-ssh off"), null);
});

test("non-guard lines return null (delegate to built-in)", () => {
  assert.equal(guardTierCompletions(""), null);
  assert.equal(guardTierCompletions("hello world"), null);
  assert.equal(guardTierCompletions("please /guard on"), null);
  assert.equal(guardTierCompletions("/guardx"), null);
  assert.equal(guardTierCompletions("/g"), null);
});

test("multi-arg or unknown-arg lines return null", () => {
  assert.equal(guardTierCompletions("/guard on extra"), null);
  assert.equal(guardTierCompletions("/guard zz"), null);
});

test("add-dir completes subcommand name via tier completion", () => {
  assert.deepEqual(
    guardTierCompletions("/guard add")!.items.map((i) => i.value),
    ["add-dir"],
  );
});

test("add-dir path completion matches entries in the parent dir", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-compl-"));
  await mkdir(join(dir, "alpha"));
  await mkdir(join(dir, "alphadir"));
  await writeFile(join(dir, "beta.txt"), "");

  const r = await guardAddDirCompletions(`/guard add-dir ${dir}/al`);
  assert.ok(r);
  assert.equal(r.prefix, `${dir}/al`);
  assert.deepEqual(
    r.items.map((i) => i.value),
    [`${dir}/alpha/`, `${dir}/alphadir/`],
  );

  // dirs sort before files, each alphabetical
  const all = await guardAddDirCompletions(`/guard add-dir ${dir}/`);
  assert.ok(all);
  assert.deepEqual(
    all!.items.map((i) => i.value),
    [`${dir}/alpha/`, `${dir}/alphadir/`, `${dir}/beta.txt`],
  );
  // directories carry a trailing slash (so Tab descends); files don't
  assert.equal(all!.items[0]!.label, "alpha/");
  assert.equal(all!.items[2]!.label, "beta.txt");
});

test("add-dir path completion: ~/ form is kept for home paths", async () => {
  const r = await guardAddDirCompletions("/guard add-dir ~/.c");
  assert.ok(r);
  assert.equal(r.prefix, "~/.c");
  assert.ok(r.items.every((i) => i.value.startsWith("~/")));
  assert.ok(r.items.some((i) => i.value === "~/.cache/"));
});

test("add-dir path completion returns null for non-matching lines", async () => {
  assert.equal(await guardAddDirCompletions("/guard o"), null);
  assert.equal(await guardAddDirCompletions("/guard add-"), null); // subcommand partial — tier completion handles it
  assert.equal(await guardAddDirCompletions("/guard add-dir"), null); // no path token yet — subcommand completion
  assert.equal(await guardAddDirCompletions("/guard add-dir /nonexistent-guard-dir/"), null);
});
