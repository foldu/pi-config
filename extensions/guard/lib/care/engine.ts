// CARE engine — Stage 1 (canonicalization) + Stage 2 (attribution L1-L5).
// Deterministic; never makes a network call. Stage 3 lives in resolution.ts.
import { performance } from "node:perf_hooks";
import { normalize } from "./canonicalize.ts";
import { analyzeStructure } from "./structure.ts";
import { buildCommandClassMap, classify } from "./semantic.ts";
import { validatePath } from "./path.ts";
import { detectPatterns } from "./pattern.ts";
import { compose, decide, DEFAULT_POLICY, type PolicyConfig } from "./policy.ts";
import { policyFor, type OperatingMode } from "./modes.ts";
import type { AnalysisResult, FiredRule, RiskClass } from "./types.ts";

export interface EngineOptions {
  /** Unused for now (kept for API parity); path layer matches on literals. */
  workspace?: string;
  mode?: OperatingMode;
  policy?: PolicyConfig;
  /** Config `commandClasses` overrides ({ CLASS: [prog, …] }, e.g.
   * { "WRITE_LOCAL": ["nix"] }). Takes precedence over the built-in lexicon
   * for generic commands; subcommand-aware heads (git, rm, chmod, dd,
   * docker/podman, kill, sed -i) keep their logic. */
  commandClasses?: Record<string, string[]>;
}

function round(n: number): number {
  return Math.round(n * 10000) / 10000;
}

export function analyze(cmd: string, options: EngineOptions = {}): AnalysisResult {
  const start = performance.now();
  const cfg = options.mode
    ? policyFor(options.mode, options.policy ?? DEFAULT_POLICY)
    : (options.policy ?? DEFAULT_POLICY);

  const triggered: string[] = [];
  const firedRules: FiredRule[] = [];

  const raw = cmd;
  const norm = normalize(cmd);

  const classMap = buildCommandClassMap(options.commandClasses);

  // L1 structure
  const ast = analyzeStructure(norm);
  if (ast.structureRisk > 0) triggered.push("L1_AST");

  // L2 semantic — per atom, take max
  const semDetails: AnalysisResult["details"]["semantic"] = [];
  let semScore = 0;
  let bestCls: RiskClass | null = null;
  for (const atom of ast.atoms) {
    const s = classify(atom, classMap);
    semDetails.push({
      atom: atom.slice(0, 120),
      riskClass: s.riskClass,
      score: s.score,
      reason: s.reason,
    });
    if (s.score > semScore) {
      semScore = s.score;
      bestCls = s.riskClass;
    }
  }
  if (semScore > 0) triggered.push("L2_Semantic");

  // L3 path
  const path = validatePath(norm);
  if (path.score > 0) triggered.push("L3_Path");

  // L4 pattern
  const pat = detectPatterns(norm);
  firedRules.push(...pat.matches);
  if (pat.score > 0) triggered.push("L4_Pattern");

  // L5 policy
  const finalScore = compose(semScore, path.score, pat.score, ast.structureRisk, cfg);
  const decision = decide(finalScore, cfg);

  const latencyMs = performance.now() - start;

  return {
    command: raw,
    normalized: norm !== raw ? norm : null,
    decision,
    score: round(finalScore),
    triggeredLayers: triggered,
    firedRules,
    details: {
      ast: {
        atoms: ast.atoms.length,
        hasPipe: ast.hasPipe,
        hasPipeToExec: ast.hasPipeToExec,
        hasCommandSub: ast.hasCommandSub,
        hasEval: ast.hasEval,
        structureRisk: ast.structureRisk,
      },
      semantic: semDetails,
      semanticMaxClass: bestCls,
      path: { score: path.score, reason: path.reason, triggered: path.triggered },
      pattern: { score: pat.score, matches: pat.matches.map((m) => m.ruleId) },
      scoring: {
        semScore: round(semScore),
        pathScore: round(path.score),
        patScore: round(pat.score),
        structScore: round(ast.structureRisk),
        finalScore: round(finalScore),
        weights: { wSem: cfg.wSem, wPath: cfg.wPath, wPat: cfg.wPat, wStruct: cfg.wStruct },
        thresholds: { tauLow: cfg.thresholdLow, tauHigh: cfg.thresholdHigh },
      },
    },
    latencyMs: round(latencyMs),
  };
}

export function isDangerous(cmd: string, options?: EngineOptions): boolean {
  return analyze(cmd, options).decision !== "ALLOW";
}
