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

/** Short plain-English meaning of each risk class (for LLM-readable reasons).
 * Its keys are the canonical set of valid class names. */
export const CLASS_MEANING: Record<RiskClass, string> = {
  READ_ONLY: "reads data",
  WRITE_LOCAL: "writes to project/local files",
  WRITE_SENSITIVE: "writes to sensitive locations (config, secrets, system dirs)",
  NETWORK_FETCH: "fetches from the network",
  EXECUTION_CHAIN: "builds a command from mutable or untrusted input",
  PRIVILEGE_OR_PERMISSION: "needs elevated privileges or changes permissions",
  PERSISTENCE: "installs, enables, or auto-starts something persistent",
  DESTRUCTIVE: "can destroy data (delete, overwrite, format)",
  RESOURCE_ABUSE: "consumes excessive resources or network traffic",
  UNKNOWN: "unrecognized behavior",
};

/** Valid class names — the keys of CLASS_MEANING (every class has a meaning).
 * Used to validate config `commandClasses` keys; the schema's propertyNames
 * enum is maintained by hand alongside it. */
export const RISK_CLASSES = Object.keys(CLASS_MEANING) as RiskClass[];

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
