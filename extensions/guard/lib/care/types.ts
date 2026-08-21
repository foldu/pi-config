// Shared types and constants for the CARE port.

export type Decision = "ALLOW" | "WARN" | "DENY";

export type RiskClass =
  | "READ_ONLY"
  | "WRITE_LOCAL"
  | "WRITE_SENSITIVE"
  | "NETWORK_FETCH"
  | "EXECUTION_CHAIN"
  | "PRIVILEGE_OR_PERMISSION"
  | "PERSISTENCE"
  | "DESTRUCTIVE"
  | "RESOURCE_ABUSE"
  | "UNKNOWN";

export const CLASS_BASE_SCORE: Record<RiskClass, number> = {
  READ_ONLY: 0.0,
  WRITE_LOCAL: 0.15,
  WRITE_SENSITIVE: 0.7,
  NETWORK_FETCH: 0.4,
  EXECUTION_CHAIN: 0.6,
  PRIVILEGE_OR_PERMISSION: 0.75,
  PERSISTENCE: 0.8,
  DESTRUCTIVE: 1.0,
  RESOURCE_ABUSE: 0.85,
  UNKNOWN: 0.35,
};

export interface FiredRule {
  ruleId: string;
  failureFamily: string;
  confidence: number;
  provenanceTier: string;
  provenanceWeight: number;
  effectiveScore: number;
  description: string;
}

export interface SemanticDetail {
  atom: string;
  riskClass: RiskClass;
  score: number;
  reason: string;
}

export interface AnalysisResult {
  /** Raw command exactly as received (pre-canonicalization). */
  command: string;
  /** Canonicalized form, or null when identical to `command`. */
  normalized: string | null;
  decision: Decision;
  score: number;
  triggeredLayers: string[];
  firedRules: FiredRule[];
  details: {
    ast: {
      atoms: number;
      hasPipe: boolean;
      hasPipeToExec: boolean;
      hasCommandSub: boolean;
      hasEval: boolean;
      structureRisk: number;
    };
    semantic: SemanticDetail[];
    semanticMaxClass: RiskClass | null;
    path: { score: number; reason: string; triggered: string[] };
    pattern: { score: number; matches: string[] };
    scoring: {
      semScore: number;
      pathScore: number;
      patScore: number;
      structScore: number;
      finalScore: number;
      weights: { wSem: number; wPath: number; wPat: number; wStruct: number };
      thresholds: { tauLow: number; tauHigh: number };
    };
  };
  latencyMs: number;
}
