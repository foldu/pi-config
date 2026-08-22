// Stage 1 — canonicalization operator N (obfuscation normalizer).
//
// Augments the raw command with deobfuscated fragments (original tokens are
// preserved) so downstream layers can match both raw and decoded forms.
// Purely syntactic: never executes anything.
import { parse } from "unbash";
import type { ParsedScript } from "unbash";
import { walkNode } from "./walk.ts";

const SHELL_NAMES = new Set(["sh", "bash", "dash", "zsh", "ash", "ksh"]);

function isPrintable(s: string): boolean {
  // Reject control chars except \n (0x0a) and \t (0x09). Intentional: CARE
  // must match control characters in shell payloads.
  // oxlint-disable-next-line no-control-regex
  return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s);
}

// -------------- IFS --------------

export function expandIfs(cmd: string): string {
  let out = cmd;
  out = out.replace(/\$\{IFS(?:[%#][^}]*)?\}/g, " ");
  out = out.replace(/\$IFS\b/g, " ");
  out = out.replace(/\$IFS([A-Za-z_]\w*)/g, " $1");
  out = out.replace(/  +/g, " ");
  return out;
}

// -------------- substitution-nesting collapse --------------

export function collapseSubstitution(cmd: string): string {
  let out = cmd;
  for (let i = 0; i < 10; i++) {
    const prev = out;
    out = out
      .replace(/`\s*echo\s+([A-Za-z0-9_./@:-]+)\s*`/g, "$1")
      .replace(/`\s*printf\s+['"]([A-Za-z0-9_./@:-]+)['"]\s*`/g, "$1")
      .replace(/\$\(\s*echo\s+([A-Za-z0-9_./@:-]+)\s*\)/g, "$1")
      .replace(/\$\(\s*printf\s+["']([A-Za-z0-9_./@:-]+)["']\s*\)/g, "$1")
      .replace(/\$\(\s*printf\s+["']%s["']\s+([A-Za-z0-9_./@:-]+)\s*\)/g, "$1")
      .replace(/\$\(\s*printf\s+["']%s["']\s+(\$\w+)\s*\)/g, "$1")
      .replace(/\$\(\s*([A-Za-z0-9_./@:-]+)(?:""|'')([A-Za-z0-9_./@:-]+)\s*\)/g, "$1$2")
      .replace(/([A-Za-z0-9_./@:-]+)(?:""|'')([A-Za-z0-9_./@:-]+)/g, "$1$2")
      .replace(/\$\(\s*\)|``/g, "");
    if (out === prev) break;
  }
  return out;
}

// -------------- variable-splitting expansion --------------

export function expandVariables(cmd: string): string {
  const assigns: Record<string, string> = {};
  const assignRe =
    /(?:^|;|\s|&&|\|\|)\s*([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|([^\s;|&]+))/g;
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(cmd)) !== null) {
    const name = m[1]!;
    const val = m[3] ?? m[4] ?? m[5] ?? "";
    if (val.length > 40 || /[()[\]<>|&;\\]/.test(val)) continue;
    assigns[name] = val;
  }
  if (Object.keys(assigns).length === 0) return cmd;

  let out = cmd;
  for (let i = 0; i < 2; i++) {
    out = out.replace(
      /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
      (_, n: string) => assigns[n] ?? `\${${n}}`,
    );
    out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_, n: string) => assigns[n] ?? `$${n}`);
  }
  return out;
}

// -------------- base64 payload inlining --------------

export function inlineBase64Payloads(cmd: string): string {
  let out = cmd;
  const pyRe = /base64\.b64decode\(['"]([A-Za-z0-9+/=]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = pyRe.exec(cmd)) !== null) {
    try {
      const dec = Buffer.from(m[1]!, "base64").toString("utf8");
      if (isPrintable(dec)) out += ` \x1f<PY_B64>${dec}</PY_B64>\x1f`;
    } catch {
      /* ignore */
    }
  }
  if (/\bbase64\s+(-d|--decode)\b/.test(cmd)) {
    const cand = /\b[A-Za-z0-9+/]{12,}={0,2}\b/g;
    while ((m = cand.exec(cmd)) !== null) {
      const s = m[0];
      if (s.length < 12 || s.length % 4 !== 0) continue;
      try {
        const dec = Buffer.from(s, "base64").toString("utf8");
        if (dec && [...dec].every((c) => isPrintable(c) || c === "\n" || c === "\t" || c === " ")) {
          out += ` \x1f<B64DEC>${dec}</B64DEC>\x1f`;
        }
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

// -------------- hex / octal printf decoding --------------

export function decodePrintfEscapes(cmd: string): string {
  let out = cmd;
  const hexRe = /printf\s+['"]((?:\\x[0-9a-fA-F]{2})+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = hexRe.exec(cmd)) !== null) {
    const bytes = (m[1]!.match(/\\x([0-9a-fA-F]{2})/g) ?? []).map((s) => s.slice(2));
    try {
      const dec = Buffer.from(bytes.join(""), "hex").toString("utf8");
      if (dec) out += ` \x1f<HEXDEC>${dec}</HEXDEC>\x1f`;
    } catch {
      /* ignore */
    }
  }
  const octRe = /printf\s+['"]((?:\\0[0-7]{2,3})+)['"]/g;
  while ((m = octRe.exec(cmd)) !== null) {
    const bytes = (m[1]!.match(/\\0([0-7]{2,3})/g) ?? []).map((s) => parseInt(s.slice(2), 8));
    try {
      const dec = Buffer.from(bytes).toString("utf8");
      if (dec) out += ` \x1f<OCTDEC>${dec}</OCTDEC>\x1f`;
    } catch {
      /* ignore */
    }
  }
  return out;
}

// -------------- shell-wrapper unwrap --------------

export function unwrapShellC(cmd: string): string {
  let ast: ParsedScript;
  try {
    ast = parse(cmd);
  } catch {
    return cmd;
  }
  const inners: string[] = [];
  for (const stmt of ast.commands) {
    walkNode(stmt, (c) => {
      if (!c.name) return;
      // Scan every word (head + args) for a `shell -c '<inner>'` pattern, not
      // just the head. This also unwraps the sandbox's `bwrap ... bash -c '...'`
      // form, where `bash` appears as an argument rather than the command head.
      const words = [c.name, ...c.suffix];
      for (let i = 0; i < words.length; i++) {
        const w = words[i]!;
        if (SHELL_NAMES.has(w.text) || w.text === "busybox") {
          let j = i + 1;
          if (w.text === "busybox" && words[j] && SHELL_NAMES.has(words[j]!.text)) j++;
          const flag = words[j];
          if (flag && flag.text.startsWith("-") && flag.text.includes("c")) {
            const inner = words[j + 1];
            if (inner && inner.value && inner.value.length > 0 && inner.value.length < 4000) {
              inners.push(inner.value);
            }
          }
        } else if (w.text === "eval" || w.text === "exec") {
          // eval/exec "<inner>" — the argument is evaluated as shell.
          const inner = words[i + 1];
          if (inner && inner.value && inner.value.length > 0 && inner.value.length < 4000) {
            inners.push(inner.value);
          }
        }
      }
    });
  }
  let out = cmd;
  for (const inner of inners) out += ` \x1f<SHELL_C>${inner}</SHELL_C>\x1f`;
  return out;
}

// -------------- public pipeline --------------

export function normalize(cmd: string): string {
  let x = expandIfs(cmd);
  x = expandVariables(x);
  x = collapseSubstitution(x);
  x = inlineBase64Payloads(x);
  x = decodePrintfEscapes(x);
  x = unwrapShellC(x);
  return x;
}
