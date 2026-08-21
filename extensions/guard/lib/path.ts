// L3 — path-sensitive validation (paper Eq. 3-4), read-vs-write aware.
import { homedir } from "node:os";
import { join } from "node:path";

function basename(p: string): string {
  const parts = p.split("/");
  return parts[parts.length - 1] ?? p;
}

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

const CRITICAL_PATH_PATTERNS: RegExp[] = [
  /^\/dev\/(sd|hd|nvme|vd|md|mmcblk|loop)/,
  /\/etc\/(shadow|gshadow|sudoers)(\s|$|\/)/,
  /\.ssh\/authorized_keys/,
  /\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/,
  /\/proc\/(sysrq-trigger|kallsyms|kcore|kmsg|self\/mem|kmem)\b/,
  /\/sys\/kernel\/(kexec|debug|tracing|security)\b/,
];

const SECRET_READ_PATHS = [
  "~/.ssh/id_", "~/.ssh/authorized_keys",
  "~/.aws/credentials", "~/.docker/config.json",
  "~/.kube/config", "~/.gnupg/", "~/.netrc",
  "~/.mysql_history",
  "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
  "/root/.ssh",
];

const SENSITIVE_WRITE_PATHS = [
  "/etc/", "/boot/", "/sys/", "/proc/sys/", "/root/",
  "/var/log/", "/var/lib/",
  "/dev/",
];

const BENIGN_DEVICE_PATHS = [
  "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
  "/dev/stdout", "/dev/stderr", "/dev/stdin",
  "/dev/tty", "/dev/pts/", "/dev/fd/",
];

const SYSTEM_ROOT_TARGETS = new Set([
  "/", "/*", "/home", "/etc", "/usr", "/var",
  "/opt", "/srv", "/boot", "/bin", "/sbin", "/lib", "/lib64",
]);

const READ_ONLY_HEADS = new Set([
  "cat", "head", "tail", "less", "more", "wc", "nl", "od", "xxd",
  "hexdump", "strings",
  "grep", "egrep", "fgrep", "rg", "ag", "ack",
  "find", "locate", "which", "whereis", "type",
  "ls", "ll", "dir", "tree", "file", "stat", "readlink", "realpath",
  "du", "df",
  "awk", "sed",
  "cut", "sort", "uniq", "tr", "column", "paste", "diff", "cmp",
  "jq", "yq",
  "echo", "printf",
  "ps", "top", "htop", "free", "uptime", "date",
  "uname", "id", "whoami", "hostname", "env", "printenv",
  "md5sum", "sha1sum", "sha256sum",
  "mount", "rsync",
]);

const WRITE_HEADS = new Set([
  "cp", "mv", "mkdir", "touch", "ln", "rm", "rmdir",
  "dd", "mkfs", "shred", "wipefs", "fdisk", "truncate", "fallocate",
  "chmod", "chown", "chgrp", "setcap",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "apt", "apt-get", "yum", "dnf", "pacman", "npm", "pip", "pip3",
  "make", "gcc", "g++", "cmake",
  "git",
]);

const DESTRUCTIVE_HEADS = new Set([
  "rm", "dd", "mkfs", "shred", "wipefs", "fdisk", "parted",
  "gdisk", "sgdisk", "cfdisk", "truncate",
]);

function headOf(cmd: string): string {
  const m = /<SHELL_C>\s*(\S+)/.exec(cmd);
  if (m) return basename(m[1]!);
  const tokens = cmd.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return "";
  return basename(tokens[0]!);
}

function hasWriteContext(cmd: string): boolean {
  const head = headOf(cmd);
  if (WRITE_HEADS.has(head)) return true;
  if (head === "sudo") {
    const toks = cmd.trim().split(/\s+/);
    if (toks.length > 1 && WRITE_HEADS.has(basename(toks[1]!))) return true;
  }
  if (/(?<![0-9&])>{1,2}\s*\S/.test(cmd)) return true;
  if (head === "sed" && /\bsed\s+[^|;]*-i\b/.test(cmd)) return true;
  if (/\btee\b\s+(-a\s+)?\S/.test(cmd)) return true;
  return false;
}

function isDestructiveHead(cmd: string): boolean {
  const head = headOf(cmd);
  if (DESTRUCTIVE_HEADS.has(head)) return true;
  if (head === "sudo") {
    const toks = cmd.trim().split(/\s+/);
    return toks.length > 1 && DESTRUCTIVE_HEADS.has(basename(toks[1]!));
  }
  if (/>\s*\/dev\/(sd|hd|nvme|vd)/.test(cmd)) return true;
  return false;
}

function stripQuotes(s: string): string {
  return s.replace(/^["']+/, "").replace(/["']+$/, "");
}

function extractPaths(cmd: string): string[] {
  const paths: string[] = [];
  let text = cmd.replace(/\x1f?<(?:B64DEC|HEXDEC|OCTDEC|PY_B64|SHELL_C)>/g, " ");
  text = text.replace(/<\/(?:B64DEC|HEXDEC|OCTDEC|PY_B64|SHELL_C)>\x1f?/g, " ");

  const tokenRe = /"[^"]+"|'[^']+'|\S+/g;
  let m: RegExpExecArray | null;
  while ((m = tokenRe.exec(text)) !== null) {
    let t = stripQuotes(m[0]);
    if (!t) continue;
    if (t.startsWith("-") && !t.startsWith("/")) {
      const eq = t.indexOf("=");
      if (eq !== -1) {
        const rhs = t.slice(eq + 1);
        if (rhs.startsWith("/") || rhs.startsWith("~") || rhs.startsWith("./") || rhs.includes("../")) {
          paths.push(rhs);
        }
      }
      continue;
    }
    if (t.startsWith("/") || t.startsWith("~") || t.startsWith("./") || t.includes("../")) {
      paths.push(t);
    }
  }

  const redirectRe = />{1,2}\s*([^\s;&|]+)/g;
  while ((m = redirectRe.exec(text)) !== null) {
    const tgt = stripQuotes(m[1]!);
    if (tgt && (tgt.startsWith("/") || tgt.startsWith("~") || tgt.startsWith("./") || tgt.includes("../"))) {
      paths.push(tgt);
    }
  }
  return paths;
}

export interface PathVerdict {
  score: number;
  reason: string;
  triggered: string[];
}

export function validatePath(cmd: string): PathVerdict {
  const paths = extractPaths(cmd);
  if (paths.length === 0) return { score: 0, reason: "paths_ok", triggered: [] };

  const head = headOf(cmd);
  const isRead = READ_ONLY_HEADS.has(head);
  const writing = hasWriteContext(cmd);
  const destructive = isDestructiveHead(cmd);

  const writeTargets = new Set<string>();
  const redirectRe = />{1,2}\s*([^\s;&|]+)/g;
  let m: RegExpExecArray | null;
  while ((m = redirectRe.exec(cmd)) !== null) {
    const t = stripQuotes(m[1]!);
    writeTargets.add(t);
    writeTargets.add(expandHome(t));
  }
  if (/\bsed\s+[^|;]*-i\b/.test(cmd)) {
    const seg = /\bsed\s+[^|;]+/.exec(cmd);
    if (seg) {
      for (const tok of seg[0].split(/\s+/)) {
        const t = stripQuotes(tok);
        if (t.startsWith("/") || t.startsWith("~")) {
          writeTargets.add(t);
          writeTargets.add(expandHome(t));
        }
      }
    }
  }
  const teeRe = /\btee\b\s+(?:-a\s+)?([^\s|&;]+)/g;
  while ((m = teeRe.exec(cmd)) !== null) {
    const t = stripQuotes(m[1]!);
    if (t.startsWith("/") || t.startsWith("~") || t.startsWith("./")) {
      writeTargets.add(t);
      writeTargets.add(expandHome(t));
    }
  }

  const triggered: string[] = [];
  let maxScore = 0;
  let reason = "paths_ok";

  for (const p of paths) {
    const expanded = expandHome(p);
    const isWriteThis = writeTargets.has(p) || writeTargets.has(expanded);

    // (a) system-root sink → hard-fail only for destructive heads
    if (SYSTEM_ROOT_TARGETS.has(p) || SYSTEM_ROOT_TARGETS.has(expanded)) {
      if (destructive) {
        triggered.push(p);
        return { score: 1.0, reason: `destructive_on_system_root:${p}`, triggered };
      }
    }

    // (b) critical patterns — device writes, secret files, authorized_keys
    for (const pat of CRITICAL_PATH_PATTERNS) {
      if (pat.test(expanded) || pat.test(p)) {
        triggered.push(p);
        return { score: 1.0, reason: `critical_path:${p}`, triggered };
      }
    }

    // (c) secret-bearing read paths — always high
    for (const sp of SECRET_READ_PATHS) {
      if (expanded.startsWith(sp) || p.startsWith(sp) || sp.replace(/^~+/, "") !== "" && expanded.includes(sp.replace(/^~+/, ""))) {
        const score = 0.85;
        if (score > maxScore) {
          maxScore = score;
          reason = `secret_path:${p}`;
        }
        if (!triggered.includes(p)) triggered.push(p);
      }
    }

    // (d) sensitive system paths — read vs write context
    if (BENIGN_DEVICE_PATHS.some((b) => expanded.startsWith(b) || p.startsWith(b))) continue;
    for (const sp of SENSITIVE_WRITE_PATHS) {
      if (expanded.startsWith(sp) || p.startsWith(sp)) {
        let score: number;
        let why: string;
        if (isWriteThis || (writing && !isRead)) {
          score = 0.7;
          why = `sensitive_write:${p}`;
        } else if (isRead && !writing) {
          score = 0.1;
          why = `sensitive_read:${p}`;
        } else {
          score = 0.35;
          why = `sensitive_ambiguous:${p}`;
        }
        if (score > maxScore) {
          maxScore = score;
          reason = why;
        }
        if (!triggered.includes(p)) triggered.push(p);
      }
    }

    // (e) path traversal
    if (p.includes("../")) {
      const score = isRead ? 0.3 : 0.5;
      if (score > maxScore) {
        maxScore = score;
        reason = `path_traversal:${p}`;
      }
      if (!triggered.includes(p)) triggered.push(p);
    }
  }

  return { score: maxScore, reason, triggered };
}
