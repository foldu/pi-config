import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "jsonc-parser";
import Ajv from "ajv";
import { splitDomainPatternPort } from "../lib/netpolicy.ts";

// Repo root: extensions/guard/test → ../../.. (config and schema live at the
// repo root, two levels above this test's parent dir).
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

const configPath = join(repoRoot, "guard.jsonc");
const schemaPath = join(repoRoot, "extensions", "guard", "guard.schema.json");

test("guard.jsonc validates against guard.schema.json (ajv)", () => {
  const config = parse(readFileSync(configPath, "utf8"), [], {
    allowTrailingComma: true,
  });
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const ajv = new Ajv({ strict: false, allErrors: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(config), true, ajv.errorsText(validate.errors));
});

test("guard.jsonc defaultTier is a valid tier", () => {
  const config = parse(readFileSync(configPath, "utf8"), [], {
    allowTrailingComma: true,
  });
  assert.ok(
    ["off", "on", "net", "isolated", "readonly"].includes(config.defaultTier),
    `unexpected defaultTier: ${config.defaultTier}`,
  );
});

test("allowedHosts/deniedHosts entries are well-formed patterns", () => {
  const config = parse(readFileSync(configPath, "utf8"), [], {
    allowTrailingComma: true,
  });
  for (const host of [...config.allowedHosts, ...config.deniedHosts]) {
    const { hostPattern } = splitDomainPatternPort(host);
    assert.ok(hostPattern.length > 0, `empty hostname in pattern "${host}"`);
    // Wildcards are refused for IP literals (see lib/netpolicy.ts).
    assert.ok(
      !/^\*\.[0-9.]+$/.test(hostPattern),
      `wildcard on IP literal in pattern "${host}"`,
    );
  }
});
