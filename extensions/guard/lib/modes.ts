// Operating modes — threshold presets over the base policy.
import { DEFAULT_POLICY, type PolicyConfig } from "./policy.ts";

export type OperatingMode = "balanced" | "strict" | "auto";

const MODE_PRESETS: Record<OperatingMode, { thresholdLow: number; thresholdHigh: number }> = {
  balanced: { thresholdLow: 0.15, thresholdHigh: 0.35 },
  strict: { thresholdLow: 0.1, thresholdHigh: 0.2 },
  auto: { thresholdLow: 0.2, thresholdHigh: 0.5 },
};

export function policyFor(mode: OperatingMode, base: PolicyConfig = DEFAULT_POLICY): PolicyConfig {
  const preset = MODE_PRESETS[mode];
  return { ...base, thresholdLow: preset.thresholdLow, thresholdHigh: preset.thresholdHigh };
}
