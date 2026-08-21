# Safety tiers

The guard operates in one of five **tiers**. A tier sets two things at once —
**containment** (how the command is sandboxed) and the **approval policy** (how CARE's
ALLOW / WARN / DENY verdict maps to auto-allow / prompt / block) — so the trust you
place in the environment and the trust you place in the machine's grading move together,
under one knob.

## The one invariant

**DENY is a hard block in every tier.** The "computer explodes" tier (`rm -rf /`,
`cat ~/.ssh/id_rsa`, reverse shells, `dd of=/dev/sd*`, …) never reaches a prompt, in
any tier — including `off`. The only way to lift a DENY is a deliberate, persistent
`overrides` entry in `guard.jsonc` (audited, not a one-click "allow anyway").

CARE always runs. `off` does not mean "guard off" — it means "no containment, so nothing
is auto-allowed."

## Tiers

| Tier | bwrap sandbox | Network | ALLOW | WARN | DENY |
|------|---------------|---------|-------|------|------|
| `off` | none — real host | host | prompt | prompt | block |
| `on` (default) | on, RO root + writable caches | **whitelist** (new hosts prompt) | auto | prompt | block |
| `net` | on | **full host** | auto | prompt | block |
| `isolated` | on | **none** | auto | prompt | block |
| `readonly` | on, **everything RO** | none | auto (reads) | prompt (reads) | block (writes too) |

### `off` — no containment, everything asked

- No bwrap wrapping; commands run against the real host.
- CARE still runs, so DENY still hard-blocks.
- **ALLOW and WARN both prompt.** There is no auto-allow of any kind — not the CARE
  ALLOW band, not the read-only rule — because there is no containment backstop. The
  read-only narrow auto-allow is disabled in this tier.
- This is the tier to use when a task genuinely needs the host unrestricted
  (e.g. `nixos-rebuild`, `docker` on the real daemon), and the price is that every
  command is reviewed.

### `on` — the default: whitelisted network, new hosts prompt

- bwrap with read-only root, the project dir + `WRITABLE_DIRS` bound writable, the real
  `/tmp` and `/var/tmp` bound writable (persistent across commands, not a fresh tmpfs),
  pid/ipc/uts namespaces, `--cap-drop ALL`.
- **Network is proxy-only egress.** The sandbox gets `--unshare-net` (zero interfaces),
  and every connection is forced through host-side HTTP + SOCKS5 proxies (reached via
  socat Unix-socket bridges bound into the sandbox, with standard proxy env vars set).
  The proxies enforce `allowedHosts` / `deniedHosts` (patterns: `github.com`,
  `*.github.com`, `:port` suffix, `*`), and **hosts matching neither list prompt the
  human** (Allow/Deny, remembered for the pi process; fail closed headless). Nothing can
  bypass the filter — IP literals, DoH, and raw sockets all die at the missing network
  interfaces. An *empty* `allowedHosts` means every host prompts.
- Requires `socat` (already a guard dependency; fails closed — no egress — if it's
  missing).
- CARE grading: **ALLOW → auto-allow**, **WARN → prompt** (the human judge),
  **DENY → block**.
- The read-only narrow auto-allow also applies: commands that only read data (read-context
  head, no writes/redirections, no secret paths, no sink pipes, no interpreter-script
  execution) are auto-allowed even if CARE would otherwise land them in WARN.

### `net` — the escape hatch: unrestricted network

- Identical bwrap to `on`, but **no `--unshare-net` and no whitelist** — the full host
  network is reachable, `allowedHosts` is ignored.
- Use this when a task needs arbitrary hosts (and the FS sandbox is still valuable);
  the whitelist posture returns the moment you switch back to `on`.

### `isolated` — no network at all

- Identical bwrap to `on`, but with plain `--unshare-net` and no proxy bridges — the
  sandbox has no interfaces and no egress. Network-fetch commands simply fail.
- This is the old `on` behavior, kept as the strict no-network tier.

### `readonly` — the agent may only read

- bwrap with **everything read-only** (the project dir is *not* bound writable; only the
  real `/tmp` and `/var/tmp` are bound writable so staged files persist), no network,
  same namespaces and caps.
- **Write-context commands are blocked** (`{ block: true, reason: "read-only mode" }`)
  before execution — fail fast rather than let them die on the read-only bind.
- **Reads are still CARE-graded**, not blindly allowed: `cat /etc/passwd` still WARNs
  (prompt), `cat /etc/shadow` still DENYs (block), ordinary reads auto-allow.
- Use this for inspection, audit, or "just explore the repo" tasks.

## Selecting a tier

`/guard <off|on|net|isolated|readonly>` sets the tier. `/guard` with no argument toggles
between `off` and `on` (the common switch). The footer shows the current tier.

The startup tier comes from `guard.jsonc` (validated by `extensions/guard/guard.schema.json`, referenced via the file's `$schema`):

```json
{
  "defaultTier": "on",
  "mode": "balanced",
  "warnPolicy": "prompt",
  "allowedReadDirs": ["/nix", "~/.rustup", "~/.cargo"],
  "writableDirs": ["~/.cargo", "~/.rustup", "~/.cache", "~/.local/share", "~/.config", "~/.npm"],
  "allowedHosts": ["github.com", "*.github.com", "registry.npmjs.org", "crates.io", "cache.nixos.org"],
  "deniedHosts": [],
  "overrides": {
    "allowHeads": [],
    "denyHeads": [],
    "allowPaths": [],
    "denyPaths": []
  }
}
```

- `defaultTier`: `off` | `on` | `net` | `isolated` | `readonly` — the tier at startup
  (runtime changes via `/guard` are process-scoped and do not persist).
- `mode`: `balanced` | `strict` | `auto` — CARE's decision thresholds (how aggressively
  a command lands in WARN vs DENY vs ALLOW).
- `warnPolicy`: `prompt` (human judge, default) | `deny` (treat WARN like DENY). This is
  orthogonal to the tier — it raises the floor for the whole guard.
- `allowedReadDirs`: directories (supports `~`) whose files auto-allow for the `read`
  tool, in addition to the project dir.
- `writableDirs`: directories bound writable inside the bwrap sandbox (`~` supported);
  everything else stays read-only. The project dir is always writable in `on`/`net`.
- `allowedHosts` / `deniedHosts`: the `on` tier's network whitelist/blacklist (patterns
  as above). Empty `allowedHosts` → every host prompts; `deniedHosts` is checked first
  and never prompts.
- `overrides`: per-head / per-path escape hatches. Prefer head+subcommand specificity —
  bare heads are coarse (GTFOBins abuses `git`). `allow*` entries are the *only* way to
  override a DENY.

## Relationship to the tiers

The old flat knobs (`requireSandboxForAutoAllow`, `autoAllow.readOnly`,
`autoAllow.careDefault`) are **replaced by the tier**. What used to be three separate
config flags is now one knob, because "should I auto-allow?" is really "how much
containment do I have?" — and that is what the tier expresses.
