// L5 — provenance-aware weighted policy (paper Eq. 6-7).
import type { Decision } from "./types.ts";

export interface PolicyConfig {
  wSem: number;
  wPath: number;
  wPat: number;
  wStruct: number;
  thresholdLow: number;
  thresholdHigh: number;
}

export const DEFAULT_POLICY: PolicyConfig = {
  wSem: 0.3,
  wPath: 0.3,
  wPat: 0.3,
  wStruct: 0.1,
  thresholdLow: 0.15,
  thresholdHigh: 0.35,
};

export function compose(
  sem: number,
  path: number,
  pat: number,
  struct: number,
  cfg: PolicyConfig,
): number {
  return cfg.wSem * sem + cfg.wPath * path + cfg.wPat * pat + cfg.wStruct * struct;
}

export function decide(score: number, cfg: PolicyConfig): Decision {
  if (score < cfg.thresholdLow) return "ALLOW";
  if (score < cfg.thresholdHigh) return "WARN";
  return "DENY";
}
