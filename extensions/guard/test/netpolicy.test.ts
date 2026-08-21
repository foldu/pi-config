import { test } from "node:test";
import assert from "node:assert/strict";
import {
  matchesDomainPattern,
  matchesDomainPatternWithPort,
  splitDomainPatternPort,
  NetworkPolicy,
} from "../lib/netpolicy.ts";

test("splitDomainPatternPort", () => {
  assert.deepEqual(splitDomainPatternPort("example.com"), { hostPattern: "example.com", port: undefined });
  assert.deepEqual(splitDomainPatternPort("example.com:443"), { hostPattern: "example.com", port: 443 });
  assert.deepEqual(splitDomainPatternPort("*:22"), { hostPattern: "*", port: 22 });
  // unbracketed IPv6 never splits
  assert.deepEqual(splitDomainPatternPort("::1"), { hostPattern: "::1", port: undefined });
  assert.deepEqual(splitDomainPatternPort("[2001:db8::1]:443"), { hostPattern: "2001:db8::1", port: 443 });
  // non-numeric suffix is not a port
  assert.deepEqual(splitDomainPatternPort("evil.com:443.allowed.com"), { hostPattern: "evil.com:443.allowed.com", port: undefined });
});

test("matchesDomainPattern", () => {
  assert.equal(matchesDomainPattern("github.com", "github.com"), true);
  assert.equal(matchesDomainPattern("GITHUB.com", "github.com"), true);
  assert.equal(matchesDomainPattern("api.github.com", "github.com"), false); // exact is not a suffix match
  assert.equal(matchesDomainPattern("api.github.com", "*.github.com"), true);
  assert.equal(matchesDomainPattern("github.com", "*.github.com"), false); // base domain is not a subdomain
  assert.equal(matchesDomainPattern("evil.github.com.evil.com", "*.github.com"), false); // no endsWith smuggling
  assert.equal(matchesDomainPattern("anything", "*"), true);
  // wildcards never match IP literals
  assert.equal(matchesDomainPattern("1.2.3.4", "*.3.4"), false);
  assert.equal(matchesDomainPattern("::ffff:1.2.3.4%x.allowed.com", "*.allowed.com"), false);
});

test("matchesDomainPatternWithPort", () => {
  assert.equal(matchesDomainPatternWithPort("github.com", 443, "github.com"), true);
  assert.equal(matchesDomainPatternWithPort("github.com", 22, "github.com"), true); // no port = every port
  assert.equal(matchesDomainPatternWithPort("github.com", 22, "github.com:443"), false);
  assert.equal(matchesDomainPatternWithPort("github.com", 22, "*:22"), true);
});

test("NetworkPolicy: denied wins, then allowed, then ask", async () => {
  const asked: string[] = [];
  const policy = new NetworkPolicy(
    ["github.com", "*.github.com"],
    ["evil.example.com"],
    async (host, port) => {
      asked.push(`${host}:${port}`);
      return true; // human says yes
    },
  );

  assert.equal(await policy.decide("github.com", 443), true); // allowed
  assert.equal(await policy.decide("api.github.com", 443), true); // wildcard
  assert.equal(await policy.decide("evil.example.com", 443), false); // denied, no ask
  assert.equal(await policy.decide("example.com", 443), true); // unmatched → ask → yes
  assert.deepEqual(asked, ["example.com:443"]);
});
