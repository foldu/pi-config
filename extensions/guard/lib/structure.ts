// L1 — structure analysis via the unbash AST (paper Eq. 1).
import { parse } from "unbash";
import type { Node, Word } from "unbash";
import { walkNode } from "./walk.ts";

export interface StructResult {
  atoms: string[];
  hasPipe: boolean;
  hasRedirect: boolean;
  hasCommandSub: boolean;
  hasEval: boolean;
  hasPipeToExec: boolean;
  parseError: boolean;
  nestedSubDepth: number;
  structureRisk: number;
}

const EXEC_INTERPRETERS = new Set([
  "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh",
  "eval", "python", "python2", "python3", "perl", "ruby", "node", "lua", "php",
]);

function headName(node: Node): string {
  if (node.type === "Command") return node.name?.text ?? "";
  if (node.type === "Statement") return headName(node.command);
  return "";
}

function score(r: StructResult): number {
  if (r.hasPipeToExec) return 1.0;
  if (r.hasEval) return 0.9;
  if (r.nestedSubDepth >= 2) return 0.6;
  if (r.hasCommandSub) return 0.3;
  if (r.hasPipe) return 0.05;
  return 0.0;
}

// Regex fallback (merged on parse error), mirroring the reference's fail-closed
// behavior when the parser cannot produce a full tree.
function applyFallback(cmd: string, r: StructResult): void {
  if (r.atoms.length === 0) r.atoms = [cmd];
  r.hasPipe = r.hasPipe || cmd.includes("|");
  r.hasRedirect = r.hasRedirect || cmd.includes(">");
  r.hasCommandSub = r.hasCommandSub || cmd.includes("$(") || cmd.includes("`");
  r.hasEval = r.hasEval || /\b(eval|source)\b/.test(cmd);
  r.hasPipeToExec =
    r.hasPipeToExec ||
    /\|\s*(bash|sh|zsh|dash|eval|python[23]?|perl|ruby|node)\b/.test(cmd);
  const dollarSubs = (cmd.match(/\$\(/g) ?? []).length;
  const backticks = Math.floor((cmd.match(/`/g) ?? []).length / 2);
  r.nestedSubDepth = Math.max(r.nestedSubDepth, dollarSubs + backticks);
}

export function analyzeStructure(cmd: string): StructResult {
  const r: StructResult = {
    atoms: [],
    hasPipe: false,
    hasRedirect: false,
    hasCommandSub: false,
    hasEval: false,
    hasPipeToExec: false,
    parseError: false,
    nestedSubDepth: 0,
    structureRisk: 0,
  };

  let ast;
  try {
    ast = parse(cmd);
  } catch {
    applyFallback(cmd, r);
    r.parseError = true;
    r.structureRisk = score(r);
    return r;
  }

  // Walk a nested script (used when descending into command/process
  // substitutions) and count nesting depth.
  const walkScript = (script: { commands: Node[] }, depth: number): void => {
    for (const stmt of script.commands) visitNode(stmt, depth);
  };

  const scanWord = (w: Word | undefined, depth: number): void => {
    if (!w) return;
    const parts = w.parts;
    if (!parts) return;
    for (const p of parts) {
      switch (p.type) {
        case "CommandExpansion":
        case "ProcessSubstitution":
          r.hasCommandSub = true;
          if (p.script) {
            r.nestedSubDepth = Math.max(r.nestedSubDepth, depth + 1);
            walkScript(p.script, depth + 1);
          }
          break;
        case "DoubleQuoted":
        case "LocaleString":
          for (const child of p.parts) {
            if (child.type === "CommandExpansion") {
              r.hasCommandSub = true;
              if (child.script) {
                r.nestedSubDepth = Math.max(r.nestedSubDepth, depth + 1);
                walkScript(child.script, depth + 1);
              }
            }
          }
          break;
        default:
          break;
      }
    }
  };

  const visitCommand = (c: { name?: Word; suffix: Word[]; redirects: unknown[] }, depth: number): void => {
    if (c.name) {
      const atom = [c.name.text, ...c.suffix.map((w) => w.text)].join(" ");
      r.atoms.push(atom);
      const head = c.name.text;
      if (head === "eval" || head === "source" || head === ".") r.hasEval = true;
      scanWord(c.name, depth);
    }
    for (const w of c.suffix) scanWord(w, depth);
    if (c.redirects.length > 0) r.hasRedirect = true;
  };

  function visitNode(node: Node, depth: number): void {
    switch (node.type) {
      case "Command":
        visitCommand(node, depth);
        break;
      case "Statement":
        if (node.redirects.length > 0) r.hasRedirect = true;
        visitNode(node.command, depth);
        break;
      case "Pipeline": {
        r.hasPipe = true;
        for (const c of node.commands) visitNode(c, depth);
        const last = node.commands[node.commands.length - 1];
        if (last && EXEC_INTERPRETERS.has(headName(last))) r.hasPipeToExec = true;
        break;
      }
      case "AndOr":
        for (const c of node.commands) visitNode(c, depth);
        break;
      case "CompoundList":
        for (const s of node.commands) visitNode(s, depth);
        break;
      case "Subshell":
        visitNode(node.body, depth);
        break;
      case "BraceGroup":
        visitNode(node.body, depth);
        break;
      case "If":
        visitNode(node.clause, depth);
        visitNode(node.then, depth);
        if (node.else) visitNode(node.else, depth);
        break;
      case "While":
        visitNode(node.clause, depth);
        visitNode(node.body, depth);
        break;
      case "For":
      case "Select":
        for (const w of node.wordlist) scanWord(w, depth);
        visitNode(node.body, depth);
        break;
      case "ArithmeticFor":
        visitNode(node.body, depth);
        break;
      case "Function":
        if (node.redirects.length > 0) r.hasRedirect = true;
        visitNode(node.body, depth);
        break;
      case "Case":
        for (const item of node.items) visitNode(item.body, depth);
        break;
      case "Coproc":
        visitNode(node.body, depth);
        break;
      default:
        break;
    }
  }

  walkScript(ast, 0);

  if (ast.errors && ast.errors.length > 0) {
    r.parseError = true;
    applyFallback(cmd, r);
  }
  if (r.atoms.length === 0) r.atoms = [cmd];

  // The canonicalizer appends <SHELL_C>inner</SHELL_C> markers when it unwraps
  // sh -c / bash -c / eval / bwrap. Emit those inners as atoms too, so the
  // semantic layer classifies the deobfuscated head (e.g. `eval "rm -rf /tmp/*"`
  // → `rm`, not `eval`).
  const shellCRe = /<SHELL_C>([\s\S]*?)<\/SHELL_C>/g;
  let sm: RegExpExecArray | null;
  while ((sm = shellCRe.exec(cmd)) !== null) {
    const inner = sm[1]!.trim();
    if (inner) r.atoms.push(inner);
  }

  r.structureRisk = score(r);
  return r;
}

// Re-export so callers that only need command atoms can use the shared walker.
export { walkNode };
