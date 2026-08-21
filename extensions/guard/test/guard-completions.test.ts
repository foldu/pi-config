import { test } from "node:test";
import assert from "node:assert/strict";
import { guardTierCompletions, GUARD_TIER_ITEMS } from "../lib/guard-completions.ts";

test("bare `/guard` offers all five tiers with an empty prefix", () => {
  const r = guardTierCompletions("/guard");
  assert.ok(r);
  assert.equal(r.prefix, "");
  assert.deepEqual(
    r.items.map((i) => i.value),
    ["off", "on", "net", "isolated", "readonly"],
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
