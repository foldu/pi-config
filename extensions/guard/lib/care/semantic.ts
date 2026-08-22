// L2 — semantic risk typing (paper Eq. 2).
import type { RiskClass } from "./types.ts";
import { CLASS_BASE_SCORE } from "./types.ts";
import { COMMAND_CLASSES, GIT_SUBCOMMAND_CLASSES } from "./lexicon.ts";

function basename(p: string): string {
  const parts = p.split("/");
  return parts[parts.length - 1] ?? p;
}

const SECRET_PATHS = [
  "/etc/shadow",
  "/etc/gshadow",
  "/etc/sudoers",
  "~/.ssh/id_",
  "~/.ssh/authorized_keys",
  "~/.aws/credentials",
  "~/.docker/config.json",
  "~/.kube/config",
  "~/.gnupg/",
  "~/.netrc",
  "/root/.ssh",
  ".bash_history",
  ".zsh_history",
  ".mysql_history",
];

export type ClassifyResult = { riskClass: RiskClass; score: number; reason: string };

export function classify(atom: string): ClassifyResult {
  const tokens = atom.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return { riskClass: "READ_ONLY", score: 0, reason: "empty" };

  const prog = basename(tokens[0]!);

  if (prog === "git" && tokens.length > 1) return classifyGit(tokens);
  if (prog === "rm") return classifyRm(tokens);
  if (prog === "chmod") return classifyChmod(tokens);
  if (prog === "dd") return classifyDd(tokens);
  if (prog === "sed" && tokens.some((t) => t.startsWith("-i")))
    return { riskClass: "WRITE_LOCAL", score: CLASS_BASE_SCORE.WRITE_LOCAL, reason: "sed_inplace" };
  if (prog === "docker" || prog === "podman") return classifyDocker(tokens);
  if (prog === "kill" || prog === "pkill" || prog === "killall") return classifyKill(tokens);

  const cls = COMMAND_CLASSES.get(prog) ?? "UNKNOWN";
  const score = CLASS_BASE_SCORE[cls];

  if (touchesSecretPath(tokens)) {
    if (cls === "WRITE_LOCAL" || cls === "READ_ONLY") {
      return {
        riskClass: "WRITE_SENSITIVE",
        score: CLASS_BASE_SCORE.WRITE_SENSITIVE,
        reason: `${prog}:secret_path`,
      };
    }
  }
  if ((prog === "rsync" || prog === "scp" || prog === "sftp") && !hasRemoteHost(tokens)) {
    return {
      riskClass: "WRITE_LOCAL",
      score: CLASS_BASE_SCORE.WRITE_LOCAL,
      reason: `${prog}:local_no_remote_host`,
    };
  }
  return { riskClass: cls, score, reason: `db_lookup:${prog}` };
}

function classifyGit(tokens: string[]): ClassifyResult {
  const sub = tokens[1] ?? "";
  const cls = GIT_SUBCOMMAND_CLASSES.get(sub) ?? "WRITE_LOCAL";
  if (
    sub === "push" &&
    tokens.some((t) => t === "-f" || t === "--force" || t === "--force-with-lease")
  )
    return { riskClass: "DESTRUCTIVE", score: 0.85, reason: "git_push_force" };
  if (sub === "reset" && tokens.includes("--hard"))
    return { riskClass: "DESTRUCTIVE", score: 0.8, reason: "git_reset_hard" };
  if (sub === "clean" && tokens.some((t) => t.startsWith("-f") || t.startsWith("-d")))
    return { riskClass: "DESTRUCTIVE", score: 0.7, reason: "git_clean_force" };
  return { riskClass: cls, score: CLASS_BASE_SCORE[cls], reason: `git_${sub}` };
}

function classifyRm(tokens: string[]): ClassifyResult {
  const flags = tokens.slice(1).filter((t) => t.startsWith("-"));
  const fstr = flags.join(" ");
  const recursive = ["-r", "-R", "--recursive"].some((x) => fstr.includes(x));
  const force = fstr.includes("-f") || fstr.includes("--force");
  const targets = tokens.slice(1).filter((t) => !t.startsWith("-"));

  if ((recursive && force) || fstr.includes("-rf") || fstr.includes("-fr")) {
    for (const p of targets) {
      if (
        ["/", "/*", "~", "~/*", "/home", "/etc", "/usr", "/var", "/boot", "/bin", "/sbin"].includes(
          p,
        )
      ) {
        return { riskClass: "DESTRUCTIVE", score: 1.0, reason: `rm_rf_critical:${p}` };
      }
    }
    return { riskClass: "DESTRUCTIVE", score: 0.9, reason: "rm_rf" };
  }
  if (recursive) return { riskClass: "DESTRUCTIVE", score: 0.7, reason: "rm_recursive" };
  return { riskClass: "WRITE_LOCAL", score: 0.3, reason: "rm_files" };
}

function classifyChmod(tokens: string[]): ClassifyResult {
  for (const t of tokens.slice(1)) {
    if (t.startsWith("-")) continue;
    if (/^[0-7]{3,4}$/.test(t)) {
      const modeStr = t.slice(-3);
      const mode = parseInt(modeStr, 8);
      const paths = tokens.slice(2).filter((p) => !p.startsWith("-"));
      const isSensitive = paths.some(
        (p) =>
          p.startsWith("/") ||
          p.startsWith("~/") ||
          p.startsWith("/etc") ||
          p.startsWith("/usr") ||
          p.startsWith("/bin") ||
          p.startsWith("/sbin"),
      );
      if (mode === 0o777 && isSensitive)
        return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.95, reason: "chmod_777_sensitive" };
      if (mode === 0o777)
        return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.8, reason: "chmod_777" };
      if (t.startsWith("4") || t.startsWith("2"))
        return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.85, reason: `chmod_suid:${t}` };
    }
    if (t.includes("+s") || t.includes("u+s") || t.includes("g+s"))
      return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.85, reason: "chmod_setuid_sym" };
    break;
  }
  return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.35, reason: "chmod_normal" };
}

function classifyDd(tokens: string[]): ClassifyResult {
  const joined = tokens.join(" ");
  if (/of=\/dev\/(sd|hd|nvme|vd|md|mmcblk|loop)/.test(joined))
    return { riskClass: "DESTRUCTIVE", score: 1.0, reason: "dd_block_device" };
  if (/of=\/dev\/(zero|null)/.test(joined))
    return { riskClass: "READ_ONLY", score: 0.1, reason: "dd_to_null" };
  return { riskClass: "DESTRUCTIVE", score: 0.6, reason: "dd_generic" };
}

function classifyDocker(tokens: string[]): ClassifyResult {
  if (tokens.includes("run") && tokens.includes("--privileged"))
    return { riskClass: "PRIVILEGE_OR_PERMISSION", score: 0.9, reason: "docker_privileged" };
  if (tokens.some((t) => t === "ps" || t === "images" || t === "logs" || t === "inspect"))
    return { riskClass: "READ_ONLY", score: 0.0, reason: "docker_read" };
  return { riskClass: "WRITE_LOCAL", score: CLASS_BASE_SCORE.WRITE_LOCAL, reason: "docker_other" };
}

function classifyKill(tokens: string[]): ClassifyResult {
  const joined = tokens.join(" ");
  if (/\bkill\s+-9?\s+(-?1|\$\$)\b/.test(joined))
    return { riskClass: "RESOURCE_ABUSE", score: 0.95, reason: "kill_init" };
  if (/\bkillall\s+(sshd|init|systemd|dbus)\b/.test(joined))
    return { riskClass: "RESOURCE_ABUSE", score: 0.9, reason: "killall_critical" };
  if (/\bpkill\s+-9\s+-u\s+root\b/.test(joined))
    return { riskClass: "RESOURCE_ABUSE", score: 0.9, reason: "pkill_root" };
  return {
    riskClass: "RESOURCE_ABUSE",
    score: CLASS_BASE_SCORE.RESOURCE_ABUSE,
    reason: "kill_generic",
  };
}

function touchesSecretPath(tokens: string[]): boolean {
  const joined = tokens.slice(1).join(" ");
  return SECRET_PATHS.some((s) => joined.includes(s));
}

function hasRemoteHost(tokens: string[]): boolean {
  const joined = tokens.slice(1).join(" ");
  return /\b[\w.-]+@[\w.-]+:/.test(joined);
}
