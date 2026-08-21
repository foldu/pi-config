/**
 * Host whitelist policy for the `net` tier (srt-style patterns).
 *
 * Pattern syntax (adapted from anthropic-experimental/sandbox-runtime's
 * domain-pattern matching):
 *  - `*`               matches everything (deny-all; useful in deniedHosts)
 *  - `*.example.com`   matches any strict subdomain of example.com
 *  - `example.com`     matches exactly (case-insensitive)
 *  - optional `:port`  suffix (`example.com:443`, `*:22`) restricts the
 *                      pattern to that destination port; without a port the
 *                      pattern matches every port.
 *
 * Wildcard suffix matching is refused for IP literals (a zone-ID payload
 * like `::ffff:1.2.3.4%x.allowed.com` must not pass an endsWith check).
 *
 * Decision order: deniedHosts first (hard deny, no prompt), then
 * allowedHosts (allow), then the ask callback (human prompt). The guard's
 * ask callback prompts the human per host; unmatched hosts default to deny
 * when no UI is available (fail closed).
 */

import { isIP } from "node:net";

export function splitDomainPatternPort(pattern: string): {
  hostPattern: string;
  port: number | undefined;
} {
  if (pattern.startsWith("[")) {
    // bracketed IPv6 literal: [addr] or [addr]:port — keep whole on ambiguity
    const close = pattern.indexOf("]");
    if (close === -1) return { hostPattern: pattern, port: undefined };
    const host = pattern.slice(1, close);
    const rest = pattern.slice(close + 1);
    if (rest === "") return { hostPattern: host, port: undefined };
    const port = parsePortSuffix(rest.startsWith(":") ? rest.slice(1) : "");
    return port === undefined
      ? { hostPattern: pattern, port: undefined }
      : { hostPattern: host, port };
  }
  const idx = pattern.lastIndexOf(":");
  if (idx === -1) return { hostPattern: pattern, port: undefined };
  if (pattern.indexOf(":") !== idx) {
    // unbracketed IPv6 literal — never split
    return { hostPattern: pattern, port: undefined };
  }
  const port = parsePortSuffix(pattern.slice(idx + 1));
  if (port === undefined) return { hostPattern: pattern, port: undefined };
  return { hostPattern: pattern.slice(0, idx), port };
}

function parsePortSuffix(suffix: string): number | undefined {
  if (!/^[1-9][0-9]{0,4}$/.test(suffix)) return undefined;
  const port = Number(suffix);
  return port > 65535 ? undefined : port;
}

/** Match a hostname against a single domain pattern. */
export function matchesDomainPattern(hostname: string, pattern: string): boolean {
  const h = hostname.toLowerCase();
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    if (isIP(h)) return false;
    const base = pattern.substring(2).toLowerCase();
    return h.endsWith("." + base);
  }
  return h === pattern.toLowerCase();
}

/** Match with an optional `:port` suffix on the pattern. */
export function matchesDomainPatternWithPort(
  hostname: string,
  port: number,
  pattern: string,
): boolean {
  const { hostPattern, port: patternPort } = splitDomainPatternPort(pattern);
  if (patternPort !== undefined && patternPort !== port) return false;
  return matchesDomainPattern(hostname, hostPattern);
}

export type HostAskCallback = (host: string, port: number) => Promise<boolean>;

/**
 * Whitelist policy: deniedHosts (hard deny) → allowedHosts → ask callback.
 */
export class NetworkPolicy {
  private readonly allowed: string[];
  private readonly denied: string[];
  private readonly ask: HostAskCallback;

  constructor(allowed: string[], denied: string[], ask: HostAskCallback) {
    this.allowed = allowed;
    this.denied = denied;
    this.ask = ask;
  }

  /** Returns true when a connection to host:port may proceed. */
  async decide(host: string, port: number): Promise<boolean> {
    const h = host.toLowerCase();
    for (const p of this.denied) {
      if (matchesDomainPatternWithPort(h, port, p)) return false;
    }
    for (const p of this.allowed) {
      if (matchesDomainPatternWithPort(h, port, p)) return true;
    }
    return this.ask(h, port);
  }
}
