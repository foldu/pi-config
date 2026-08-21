// Stage 3 — Resolution (skip predicates only; no LLM judge).
//
// DENY is a hard block; the remaining WARN band is escalated to the human.
// Skip predicates promote high-confidence WARNs to DENY (hard block, no prompt),
// mirroring the paper's static finalize for high-confidence denies.
import type { AnalysisResult, Decision, RiskClass } from "./types.ts";

const THETA_RULE = 0.8;
const THETA_SEM = 0.7;

const L2_HIGH_RISK_CLASSES = new Set<RiskClass>([
  "WRITE_SENSITIVE",
  "EXECUTION_CHAIN",
  "PRIVILEGE_OR_PERMISSION",
  "PERSISTENCE",
  "DESTRUCTIVE",
  "RESOURCE_ABUSE",
]);

export function resolveSkip(r: AnalysisResult): { skip: boolean; reason: string | null } {
  // p_rule: MITRE-provenanced high-confidence rule.
  for (const m of r.firedRules) {
    if (m.provenanceTier === "mitre" && m.confidence >= THETA_RULE) {
      return { skip: true, reason: `p_rule:${m.ruleId}` };
    }
  }
  // p_spath (paper Eq. 11): write-context access to a protected path, or any
  // access to a secret-bearing path. The path layer scores those >= 0.7
  // (sensitive_write=0.7, secret=0.85, critical/destructive=1.0). Milder hits
  // (sensitive_read=0.1, path traversal=0.3-0.5) must NOT skip — they stay WARN
  // for the human, not auto-DENY.
  if (r.details.path.score >= 0.7) {
    return { skip: true, reason: "p_spath" };
  }
  // p_sem: high-risk L2 semantic class.
  for (const s of r.details.semantic) {
    if (L2_HIGH_RISK_CLASSES.has(s.riskClass) && s.score >= THETA_SEM) {
      return { skip: true, reason: `p_sem:${s.riskClass}` };
    }
  }
  return { skip: false, reason: null };
}

export function resolve(r: AnalysisResult): { decision: Decision; skipReason: string | null } {
  if (r.decision !== "WARN") return { decision: r.decision, skipReason: null };
  const { skip, reason } = resolveSkip(r);
  if (skip) return { decision: "DENY", skipReason: reason };
  return { decision: "WARN", skipReason: null };
}
