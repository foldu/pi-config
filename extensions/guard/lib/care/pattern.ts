// L4 — high-confidence dangerous-pattern detection (paper Eq. 5).
// 139 provenance-tagged rules ported from the reference implementation.
//
// Two deliberate fixes vs. the reference (noted inline): SE-P-077/SE-P-080 used
// `\\\\x` (matches two literal backslashes) where `\\x` (one backslash) is
// intended, and SE-P-131 duplicated `esyscmd` on both alternation branches
// instead of `esyscmd|syscmd`.
import type { FiredRule } from "./types.ts";

interface RuleSpec {
  ruleId: string;
  pattern: string;
  failureFamily: string;
  confidence: number;
  provenanceTier: string;
  mitreTechniques: string[];
  description: string;
}

const RULES: RuleSpec[] = [
  // F1 — destructive execution
  { ruleId: "SE-P-001", pattern: String.raw`\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+/(\s|$|\*)`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485", "T1070.004"], description: "rm -rf /" },
  { ruleId: "SE-P-002", pattern: String.raw`\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+(~/?|\$HOME)(\s|$|/\*)`, failureFamily: "F1", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "rm -rf ~" },
  { ruleId: "SE-P-003", pattern: String.raw`\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+(/home|/etc|/usr|/var|/boot|/bin|/sbin|/opt)\b`, failureFamily: "F1", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "rm -rf on system dir" },
  { ruleId: "SE-P-004", pattern: String.raw`\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+--no-preserve-root`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "rm -rf --no-preserve-root" },
  { ruleId: "SE-P-005", pattern: String.raw`\bdd\s+if=/dev/(zero|urandom|random)\s+of=/dev/(sd|hd|nvme|vd|md|mmcblk)`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485", "T1561"], description: "dd wipe to block device" },
  { ruleId: "SE-P-006", pattern: String.raw`\bmkfs(\.\w+)?\s+/dev/(sd|hd|nvme|vd)`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485", "T1561"], description: "mkfs on block device" },
  { ruleId: "SE-P-007", pattern: String.raw`>\s*/dev/(sd|hd|nvme|vd|mmcblk)[a-z]\w*`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "redirect to block device" },
  { ruleId: "SE-P-008", pattern: String.raw`\bshred\s+(-[a-zA-Z]*\s+)?/dev/(sd|hd|nvme)`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "shred block device" },
  { ruleId: "SE-P-009", pattern: String.raw`\bwipefs\s+(-a\s+)?/dev/`, failureFamily: "F1", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "wipefs filesystem signatures" },
  { ruleId: "SE-P-010", pattern: String.raw`\bfind\s+/\s+.*-delete\b`, failureFamily: "F1", confidence: 0.85, provenanceTier: "manual", mitreTechniques: [], description: "find / -delete" },
  { ruleId: "SE-P-011", pattern: String.raw`>\s*/(etc|boot)/\S+`, failureFamily: "F1", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1485", "T1070"], description: "redirect overwrite to system config" },
  { ruleId: "SE-P-012", pattern: String.raw`\btruncate\s+-s\s*0\s+/etc/`, failureFamily: "F1", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1485"], description: "truncate system file" },

  // F2 — workspace escape / exfil prep
  { ruleId: "SE-P-013", pattern: String.raw`\bfind\s+/\s+.*-type\s+f.*-name\s+["']\*(env|key|secret|cred)`, failureFamily: "F2", confidence: 0.75, provenanceTier: "gtfobins", mitreTechniques: [], description: "find secrets globally" },
  { ruleId: "SE-P-014", pattern: String.raw`\.\./\.\./\.\./`, failureFamily: "F2", confidence: 0.65, provenanceTier: "manual", mitreTechniques: [], description: "deep path traversal" },
  { ruleId: "SE-P-015", pattern: String.raw`\bchroot\s+/`, failureFamily: "F2", confidence: 0.7, provenanceTier: "manual", mitreTechniques: [], description: "chroot escape" },

  // F3 — credential / secret exposure
  { ruleId: "SE-P-016", pattern: String.raw`\bcat\s+/etc/shadow\b`, failureFamily: "F3", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1552.001", "T1003.008"], description: "cat /etc/shadow" },
  { ruleId: "SE-P-017", pattern: String.raw`\bcat\s+/etc/passwd\b`, failureFamily: "F3", confidence: 0.75, provenanceTier: "mitre", mitreTechniques: ["T1087.001"], description: "cat /etc/passwd" },
  { ruleId: "SE-P-018", pattern: String.raw`\bcat\s+~/\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b`, failureFamily: "F3", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1552.004"], description: "ssh private key read" },
  { ruleId: "SE-P-019", pattern: String.raw`\bcat\s+~/\.aws/credentials\b`, failureFamily: "F3", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1552.001"], description: "AWS credentials read" },
  { ruleId: "SE-P-020", pattern: String.raw`\bcat\s+~/\.docker/config\.json\b`, failureFamily: "F3", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1552.001"], description: "Docker config read" },
  { ruleId: "SE-P-021", pattern: String.raw`\bcat\s+~/\.netrc\b`, failureFamily: "F3", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1552.004"], description: "netrc credentials read" },
  { ruleId: "SE-P-022", pattern: String.raw`\bcat\s+(~/\.bash_history|~/\.zsh_history)\b`, failureFamily: "F3", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1552.003"], description: "shell history read" },
  { ruleId: "SE-P-023", pattern: String.raw`\bhistory\s+-c\s*(\s*&\s*&|;|\n).*>\s*~/\.bash_history`, failureFamily: "F3", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1070.003"], description: "history clear and overwrite" },
  { ruleId: "SE-P-024", pattern: String.raw`(scp|rsync)\s+.*/etc/(shadow|passwd|sudoers)\s+\S+@`, failureFamily: "F3", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1048"], description: "exfiltrate system creds" },
  { ruleId: "SE-P-025", pattern: String.raw`(curl|wget)\s+.*--data(-binary)?\s+@?/etc/(shadow|passwd)`, failureFamily: "F3", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1048.003"], description: "upload creds via curl/wget" },
  { ruleId: "SE-P-026", pattern: String.raw`\btar\s+c[a-z]*f?\s+-\s+.*/etc/\s*\|\s*(curl|wget|nc)`, failureFamily: "F3", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1048"], description: "tar pipe to exfil" },
  { ruleId: "SE-P-027", pattern: String.raw`\b(scp|rsync)\s+-r?\s+~/\.ssh\s+\S+@`, failureFamily: "F3", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1552.004"], description: "exfiltrate ssh keys" },
  { ruleId: "SE-P-028", pattern: String.raw`\bgrep\s+-[a-zA-Z]*r[a-zA-Z]*\s+["'](?:password|token|api[_-]?key|secret)`, failureFamily: "F3", confidence: 0.75, provenanceTier: "manual", mitreTechniques: [], description: "grep for secrets" },
  { ruleId: "SE-P-029", pattern: String.raw`\bhexdump\s+.*\.gnupg`, failureFamily: "F3", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1552"], description: "dump gpg keyring" },
  { ruleId: "SE-P-030", pattern: String.raw`\bxxd\s+/etc/shadow`, failureFamily: "F3", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1003.008"], description: "xxd shadow" },

  // F4 — download-and-execute
  { ruleId: "SE-P-031", pattern: String.raw`(curl|wget)\s+[^|;&]*\|\s*(bash|sh|zsh|dash)\b`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1059.004"], description: "curl/wget | shell" },
  { ruleId: "SE-P-032", pattern: String.raw`(curl|wget)\s+[^|;&]*\|\s*sudo\s+(bash|sh)`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "curl/wget | sudo shell" },
  { ruleId: "SE-P-033", pattern: String.raw`bash\s+<\s*\(\s*(curl|wget)`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "bash <(curl/wget)" },
  { ruleId: "SE-P-034", pattern: String.raw`source\s+<\s*\(\s*(curl|wget)`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "source <(curl/wget)" },
  { ruleId: "SE-P-035", pattern: String.raw`(curl|wget)\s+.*-[a-zA-Z]*o\s+\S+\s*&&\s*chmod\s+\+x\s+\S+\s*&&\s*\./?\S+`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "download -> chmod +x -> run" },
  { ruleId: "SE-P-036", pattern: String.raw`bash\s+-c\s+["'\$]\(\s*(curl|wget)`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "bash -c $(curl ...)" },
  { ruleId: "SE-P-037", pattern: String.raw`eval\s+["'\$]\(\s*(curl|wget)`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1059.004"], description: "eval $(curl ...)" },
  { ruleId: "SE-P-038", pattern: String.raw`python[23]?\s+-c\s+["'].*urllib.*\b(urlopen|Request).*\bexec\s*\(`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1059.006"], description: "python urllib exec" },
  { ruleId: "SE-P-039", pattern: String.raw`python[23]?\s+-c\s+["'].*requests\.get.*\bexec\s*\(`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1059.006"], description: "python requests exec" },
  { ruleId: "SE-P-040", pattern: String.raw`perl\s+-e\s+["'].*use\s+LWP.*system\s*\(`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "perl LWP system" },

  // F5 — persistence
  { ruleId: "SE-P-041", pattern: String.raw`(echo|printf)\s+[^|]*\|\s*crontab\s+-`, failureFamily: "F5", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1053.003"], description: "echo | crontab -" },
  { ruleId: "SE-P-042", pattern: String.raw`\bcrontab\s+-[eul]?\s*$`, failureFamily: "F5", confidence: 0.65, provenanceTier: "mitre", mitreTechniques: ["T1053.003"], description: "crontab edit" },
  { ruleId: "SE-P-043", pattern: String.raw`>>\s*/etc/cron\.\w+/`, failureFamily: "F5", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1053.003"], description: "append to /etc/cron.*" },
  { ruleId: "SE-P-044", pattern: String.raw`>>\s*~/\.(bashrc|profile|bash_profile|zshrc|zprofile)`, failureFamily: "F5", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1546.004"], description: "append to shell rc" },
  { ruleId: "SE-P-045", pattern: String.raw`>>\s*/etc/(rc\.local|profile|bashrc)\b`, failureFamily: "F5", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1037"], description: "append to system init" },
  { ruleId: "SE-P-046", pattern: String.raw`(echo|printf|cat)\s+[^|]*ssh-(rsa|ed25519|ecdsa)\s+[^|]*\s*>>\s*~?/?\.?ssh/authorized_keys`, failureFamily: "F5", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1098.004"], description: "add SSH key to authorized_keys" },
  { ruleId: "SE-P-047", pattern: String.raw`\bln\s+-sf?\s+\S+\s+/etc/cron\.`, failureFamily: "F5", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1053.003"], description: "symlink into /etc/cron.*" },
  { ruleId: "SE-P-048", pattern: String.raw`\bsystemctl\s+enable\s+\S+\.service`, failureFamily: "F5", confidence: 0.55, provenanceTier: "mitre", mitreTechniques: ["T1543.002"], description: "systemctl enable unit" },
  { ruleId: "SE-P-049", pattern: String.raw`>\s*/etc/systemd/system/\S+\.service\b`, failureFamily: "F5", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1543.002"], description: "write systemd unit" },
  { ruleId: "SE-P-050", pattern: String.raw`\binstall\s+.*\bPreLoad\b|\bLD_PRELOAD\b=\S+.*\$SHELL`, failureFamily: "F5", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1574.006"], description: "LD_PRELOAD hijack" },
  { ruleId: "SE-P-051", pattern: String.raw`\becho\s+\S+\s*>>\s*/etc/ld\.so\.preload\b`, failureFamily: "F5", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1574.006"], description: "ld.so.preload write" },
  { ruleId: "SE-P-052", pattern: String.raw`\bat\s+(now|\+\d+).*<`, failureFamily: "F5", confidence: 0.65, provenanceTier: "mitre", mitreTechniques: ["T1053.001"], description: "at-job scheduling" },

  // F6 — permission broadening
  { ruleId: "SE-P-053", pattern: String.raw`\bchmod\s+0?7?777\s+/`, failureFamily: "F6", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1222.002"], description: "chmod 777 on root-level path" },
  { ruleId: "SE-P-054", pattern: String.raw`\bchmod\s+0?7?777\s+/etc/\S+`, failureFamily: "F6", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1222.002"], description: "chmod 777 /etc/*" },
  { ruleId: "SE-P-055", pattern: String.raw`\bchmod\s+[24][0-7]{3}\b`, failureFamily: "F6", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1548.001"], description: "chmod SUID/SGID numeric" },
  { ruleId: "SE-P-056", pattern: String.raw`\bchmod\s+(\+s|u\+s|g\+s)\b`, failureFamily: "F6", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1548.001"], description: "chmod +s setuid" },
  { ruleId: "SE-P-057", pattern: String.raw`\bchown\s+(root|0)(:|\s)`, failureFamily: "F6", confidence: 0.55, provenanceTier: "manual", mitreTechniques: [], description: "chown to root" },
  { ruleId: "SE-P-058", pattern: String.raw`\bsetcap\s+\S*cap_\S+\s+\S+`, failureFamily: "F6", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1548"], description: "setcap capability grant" },
  { ruleId: "SE-P-059", pattern: String.raw`NOPASSWD\s*:\s*ALL`, failureFamily: "F6", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1548.003"], description: "NOPASSWD sudo rule" },
  { ruleId: "SE-P-060", pattern: String.raw`(echo|printf)\s+[^|]*NOPASSWD[^|]*>>\s*/etc/sudoers`, failureFamily: "F6", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1548.003"], description: "append NOPASSWD to sudoers" },
  { ruleId: "SE-P-061", pattern: String.raw`\busermod\s+-a?G\s+(sudo|wheel|admin|root)\b`, failureFamily: "F6", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1136.001"], description: "add user to privileged group" },
  { ruleId: "SE-P-062", pattern: String.raw`\buseradd\s+.*-u\s*0\b`, failureFamily: "F6", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1136.001"], description: "create UID-0 user" },
  { ruleId: "SE-P-063", pattern: String.raw`\bpasswd\s+root\b`, failureFamily: "F6", confidence: 0.75, provenanceTier: "mitre", mitreTechniques: ["T1098"], description: "reset root password" },

  // F7 — resource abuse / impact
  { ruleId: "SE-P-064", pattern: String.raw`:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}[^:]*:`, failureFamily: "F7", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "classic fork bomb" },
  { ruleId: "SE-P-065", pattern: String.raw`\(\s*\)\s*\{\s*\$0\s*\|\s*\$0`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "fork-bomb variant" },
  { ruleId: "SE-P-066", pattern: String.raw`\bkill\s+-9?\s+(-?1|\$\$|0)\b`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1489"], description: "kill init or self-session" },
  { ruleId: "SE-P-067", pattern: String.raw`\bkillall\s+(sshd|init|systemd|dbus)\b`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1489"], description: "killall critical daemons" },
  { ruleId: "SE-P-068", pattern: String.raw`\bpkill\s+-9?\s+-u\s+root\b`, failureFamily: "F7", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1489"], description: "pkill root-owned processes" },
  { ruleId: "SE-P-069", pattern: String.raw`\b(shutdown|reboot|halt|poweroff)\b(?!\s+--help)`, failureFamily: "F7", confidence: 0.75, provenanceTier: "mitre", mitreTechniques: ["T1529"], description: "system shutdown/reboot" },
  { ruleId: "SE-P-070", pattern: String.raw`while\s+(true|:)\s*;\s*do\s+dd\s+if=/dev/(zero|urandom)\s+of=`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "infinite dd loop (disk fill)" },
  { ruleId: "SE-P-071", pattern: String.raw`\bfallocate\s+-l\s+\d+[TGM]\s+/tmp/`, failureFamily: "F7", confidence: 0.8, provenanceTier: "manual", mitreTechniques: [], description: "fallocate large" },
  { ruleId: "SE-P-072", pattern: String.raw`\byes\s+>\s*/dev/null\s*&`, failureFamily: "F7", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "yes > /dev/null & (CPU-spin DoS)" },
  { ruleId: "SE-P-073", pattern: String.raw`\bstress(-ng)?\s+--(cpu|vm|io)`, failureFamily: "F7", confidence: 0.7, provenanceTier: "manual", mitreTechniques: [], description: "stress load generator" },
  { ruleId: "SE-P-074", pattern: String.raw`\bhping3\b.*--flood`, failureFamily: "F7", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1499"], description: "hping3 flood" },

  // F8-related — obfuscated forms
  { ruleId: "SE-P-075", pattern: String.raw`\bbase64\s+(-d|--decode)\b[^|]*\|\s*(bash|sh|zsh|eval)`, failureFamily: "F1", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1027", "T1059.004"], description: "base64 decode | shell" },
  { ruleId: "SE-P-076", pattern: String.raw`\beval\s+["']?\$\s*\(\s*(echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d)`, failureFamily: "F1", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1027"], description: "eval $(base64 decode)" },
  { ruleId: "SE-P-077", pattern: String.raw`printf\s+["']?(\\x[0-9a-fA-F]{2}){4,}["']?\s*\|\s*(bash|sh)`, failureFamily: "F1", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1027.002"], description: "printf hex | shell" },
  { ruleId: "SE-P-078", pattern: String.raw`\brev\s*\|\s*(bash|sh)\b`, failureFamily: "F1", confidence: 0.9, provenanceTier: "manual", mitreTechniques: [], description: "rev | shell" },
  { ruleId: "SE-P-079", pattern: String.raw`\bxxd\s+-r\s+-p\b[^|]*\|\s*(bash|sh)`, failureFamily: "F1", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1027"], description: "xxd -r -p | shell" },
  { ruleId: "SE-P-080", pattern: String.raw`\$\(\s*printf\s+["']?\\x[0-9a-fA-F]{2}`, failureFamily: "F1", confidence: 0.75, provenanceTier: "mitre", mitreTechniques: ["T1027.002"], description: "hex printf substitution" },

  // Reverse shell / network back-channel
  { ruleId: "SE-P-081", pattern: String.raw`bash\s+-i\s+>&\s*/dev/tcp/`, failureFamily: "F2", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1059.004", "T1071.001"], description: "bash reverse shell" },
  { ruleId: "SE-P-082", pattern: String.raw`\bnc\s+(-[a-zA-Z]*e|--exec)\s+/bin/(ba)?sh`, failureFamily: "F2", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1059.004"], description: "nc -e reverse shell" },
  { ruleId: "SE-P-083", pattern: String.raw`python[23]?\s+-c\s+["'][^"']*socket\.socket[^"']*connect[^"']*dup2`, failureFamily: "F2", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1059.006"], description: "python socket reverse shell" },
  { ruleId: "SE-P-084", pattern: String.raw`(mknod|mkfifo)\s+\S+\s+p\b`, failureFamily: "F2", confidence: 0.75, provenanceTier: "manual", mitreTechniques: [], description: "named pipe (fifo) for callback" },

  // Extended F4 coverage
  { ruleId: "SE-P-085", pattern: String.raw`chmod\s+\+x\s+\S+\.sh\b.*\n?.*\bbash\s+\S+\.sh`, failureFamily: "F4", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1059.004", "T1105"], description: "chmod+x then bash script staging" },
  { ruleId: "SE-P-086", pattern: String.raw`awk\s+["']BEGIN\s*\{[^}]*system\s*\(`, failureFamily: "F4", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1059.004"], description: "awk BEGIN system call" },
  { ruleId: "SE-P-087", pattern: String.raw`perl\s+-MIO::Socket\b`, failureFamily: "F4", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1059.006"], description: "perl IO::Socket inline module" },
  { ruleId: "SE-P-088", pattern: String.raw`(echo|printf)\s+\$\S+\s*\|\s*(/bin/)?(sh|bash)\b`, failureFamily: "F4", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1059.004"], description: "env-var echo pipe to shell" },
  { ruleId: "SE-P-089", pattern: String.raw`python[23]?\s+-c\s+["'][^"']*urllib.*os\.system`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1059.006"], description: "python urllib + os.system" },
  { ruleId: "SE-P-090", pattern: String.raw`\$\(\s*curl\b[^)]*\)\s*\|\s*xargs\s+[^|]*\bbash\s+-c`, failureFamily: "F4", confidence: 0.9, provenanceTier: "manual", mitreTechniques: [], description: "curl substitution piped to xargs bash" },
  { ruleId: "SE-P-091", pattern: String.raw`eval\s+["']?\$\s*\(\s*wget\b`, failureFamily: "F4", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "eval wget fetch output" },
  { ruleId: "SE-P-092", pattern: String.raw`sh\s+<\s*\(\s*(curl|wget)`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "sh <(curl/wget) process sub" },
  { ruleId: "SE-P-093", pattern: String.raw`(curl|wget)\b[^|]*\|\s*sudo\s+-E?\s*bash\b`, failureFamily: "F4", confidence: 1.0, provenanceTier: "mitre", mitreTechniques: ["T1105"], description: "curl/wget | sudo -E bash" },

  // Extended F7 coverage
  { ruleId: "SE-P-094", pattern: String.raw`(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "generic named fork bomb" },
  { ruleId: "SE-P-095", pattern: String.raw`perl\s+-e\s+["']?fork\s+while\s+\d`, failureFamily: "F7", confidence: 0.95, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "perl fork while loop" },
  { ruleId: "SE-P-096", pattern: String.raw`python[23]?\s+-c\s+["'][^"']*os\.fork\b`, failureFamily: "F7", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1499.001"], description: "python os.fork loop" },
  { ruleId: "SE-P-097", pattern: String.raw`systemctl\s+(stop|disable|mask)\s+(cron|sshd|firewalld|ufw|auditd|rsyslog)\b`, failureFamily: "F7", confidence: 0.9, provenanceTier: "mitre", mitreTechniques: ["T1489"], description: "systemctl stop critical daemon" },
  { ruleId: "SE-P-098", pattern: String.raw`\bhead\s+-c\s+\d+[TG]\s+<\s*/dev/(zero|urandom|random)\s*>\s*`, failureFamily: "F7", confidence: 0.9, provenanceTier: "manual", mitreTechniques: [], description: "head -c huge → file (disk fill)" },
  { ruleId: "SE-P-099", pattern: String.raw`ulimit\s+-u\s+unlimited\s*;\s*while\s+(true|:)`, failureFamily: "F7", confidence: 0.85, provenanceTier: "manual", mitreTechniques: [], description: "ulimit -u unlimited + infinite loop" },
  { ruleId: "SE-P-100", pattern: String.raw`\b(dscl\s+\S+\s+-delete\s+/Users/|sysadminctl\s+-deleteUser)\b`, failureFamily: "F7", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1531"], description: "macOS user account delete" },
  { ruleId: "SE-P-101", pattern: String.raw`(yes\s+>\s*/dev/null\s+&\s+){2,}`, failureFamily: "F7", confidence: 0.8, provenanceTier: "manual", mitreTechniques: [], description: "multi-instance yes > /dev/null" },

  // Extended F3 credential-reconnaissance
  { ruleId: "SE-P-102", pattern: String.raw`\b(cat|less|more|head|tail|xxd|strings|grep|awk|sed)\s+[^|;&]*/etc/(pam\.d/|security/|login\.defs|passwd\b|group\b)`, failureFamily: "F3", confidence: 0.8, provenanceTier: "mitre", mitreTechniques: ["T1201", "T1087.001"], description: "password-policy / account discovery read" },
  { ruleId: "SE-P-103", pattern: String.raw`\b(scp|rsync|sftp)\s+[^|]*\b[\w.-]+@[\w.-]+:`, failureFamily: "F3", confidence: 0.75, provenanceTier: "mitre", mitreTechniques: ["T1105", "T1048"], description: "cross-host file transfer (exfil/ingress)" },
  { ruleId: "SE-P-104", pattern: String.raw`\bexport\s+(https?_proxy|HTTPS?_PROXY)=\S+:\d+`, failureFamily: "F3", confidence: 0.7, provenanceTier: "mitre", mitreTechniques: ["T1090.001"], description: "HTTP proxy hijack for traffic interception" },
  { ruleId: "SE-P-105", pattern: String.raw`\bnetworksetup\s+-set(web|secure|socks)proxy\b`, failureFamily: "F3", confidence: 0.8, provenanceTier: "mitre", mitreTechniques: ["T1090.001"], description: "macOS network proxy redirect" },
  { ruleId: "SE-P-106", pattern: String.raw`\becho\s+-e\s+["'][^"']*\be\s+/etc/(passwd|shadow)[^"']*["']\s*\|\s*ed`, failureFamily: "F3", confidence: 0.85, provenanceTier: "mitre", mitreTechniques: ["T1003.008"], description: "ed in-place editor dump of passwd/shadow" },

  // GTFOBins dual-use lexicon — F2 shell spawn via non-shell binary
  { ruleId: "SE-P-107", pattern: String.raw`\b(tmate|genie|setarch|ssh-agent|bundle\s+exec|ranger|crash|vagrant)\s+(-c\s+['"]?)?/bin/(ba|da|z)?sh\b`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "dual-use binary spawns /bin/sh" },
  { ruleId: "SE-P-108", pattern: String.raw`\bfind\s+[^|;]{0,80}-exec\s+/bin/(ba)?sh\b`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "find -exec /bin/sh" },
  { ruleId: "SE-P-109", pattern: String.raw`\b(SYSTEMD_EDITOR|SYSTEMD_PAGER|CRASHPAGER|EDITOR|VISUAL|PAGER)=[^\s]+\s+(systemctl\s+edit|sudoedit|crash|less|more|man|view)\b`, failureFamily: "F2", confidence: 0.8, provenanceTier: "gtfobins", mitreTechniques: ["T1548.003"], description: "EDITOR/PAGER env override + privileged invoker" },
  { ruleId: "SE-P-110", pattern: String.raw`\b(php|ruby|perl)\s+-[rec]\s+['"][^'"]*\b(shell_exec|system|exec|Kernel\.(exec|system)|Process\.spawn|passthru|popen|proc_open)\s*\(\s*['"][^'"]*(/bin/(ba)?sh|\$)`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004", "T1059.006"], description: "interpreter inline shell spawn" },
  { ruleId: "SE-P-111", pattern: String.raw`--config\s+alias\.[a-zA-Z0-9_]+=['"]?!\s*/bin/(ba)?sh|alias\.[a-zA-Z0-9_]+=['"]?!\s*/bin/(ba)?sh`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "hg/git config alias injects !/bin/sh" },
  { ruleId: "SE-P-112", pattern: String.raw`\bdocker\s+run\s+[^|;]*--privileged\b`, failureFamily: "F2", confidence: 0.8, provenanceTier: "gtfobins", mitreTechniques: ["T1611"], description: "docker run --privileged (container escape)" },

  // GTFOBins — F2 reverse-shell patterns
  { ruleId: "SE-P-113", pattern: String.raw`\b(gawk|awk|mawk)\s+['"]BEGIN\s*\{[^}]*/inet/tcp/`, failureFamily: "F2", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001", "T1059.004"], description: "awk BEGIN /inet/tcp (gawk reverse shell)" },
  { ruleId: "SE-P-114", pattern: String.raw`fsockopen\s*\([^)]+\)\s*[;)][\s\S]{0,120}\b(exec|system|passthru)\s*\(['"]/bin/(ba)?sh`, failureFamily: "F2", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001", "T1059.004"], description: "PHP fsockopen + exec /bin/sh" },
  { ruleId: "SE-P-115", pattern: String.raw`\bTCPSocket\.new\s*\(['"]?[\w.-]+['"]?\s*,\s*\d+\s*\)[\s\S]{0,200}(/bin/(ba|z)?sh|c\.gets)`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001", "T1059.006"], description: "Ruby TCPSocket + shell callback" },
  { ruleId: "SE-P-116", pattern: String.raw`\bmkfifo\s+\S+[\s\S]{0,200}\|\s*(nc|ncat|openssl|telnet|socat)\b`, failureFamily: "F2", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001"], description: "mkfifo + nc/openssl/telnet pipe" },
  { ruleId: "SE-P-117", pattern: String.raw`\bsocat\s+[^|]*(tcp[\-:]connect|tcp[0-9]*:)[^|]*exec:\s*['"]?/bin/(ba)?sh`, failureFamily: "F2", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001", "T1059.004"], description: "socat tcp-connect + exec:/bin/sh" },

  // GTFOBins — F4 network-fetch / download abuse
  { ruleId: "SE-P-118", pattern: String.raw`\bsmbclient\s+[^|]*-c\s+['"](get|put)\s+/(etc|root|home|var)/`, failureFamily: "F3", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1105", "T1048"], description: "smbclient get/put system file" },
  { ruleId: "SE-P-119", pattern: String.raw`file:///+(etc/(shadow|passwd|sudoers|pam\.d)|root/|home/[^/]+/\.(ssh|aws|gnupg|docker|kube))`, failureFamily: "F3", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1552.001", "T1003.008"], description: "file:// scheme to secret path" },
  { ruleId: "SE-P-120", pattern: String.raw`\b(wget|curl|aria2c|lwp-download|ab)\s+[^|]*https?://[^\s]+/etc/(shadow|passwd|sudoers)\b`, failureFamily: "F3", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1105", "T1552.001"], description: "HTTP fetch to system cred path" },
  { ruleId: "SE-P-121", pattern: String.raw`\bwhois\s+-h\s+[\w.-]+\s+-p\s+\d+\s+\S+`, failureFamily: "F4", confidence: 0.75, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001"], description: "whois -h/-p exfil channel" },
  { ruleId: "SE-P-122", pattern: String.raw`\btftp\s+(-[a-z]+\s+)?[\w.-]+\s+(get|put)\s+/(etc|root|home)/`, failureFamily: "F4", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1105"], description: "tftp get/put system path" },

  // GTFOBins — upload / exfil-listener patterns
  { ruleId: "SE-P-123", pattern: String.raw`\bnc\s+(-[a-zA-Z]*l[a-zA-Z]*|--listen)\s+[^|]*<\s*/(etc/(shadow|passwd|sudoers)|root/|home/[^/]+/\.(ssh|aws))`, failureFamily: "F3", confidence: 0.95, provenanceTier: "gtfobins", mitreTechniques: ["T1048"], description: "nc listen redirecting from secret" },
  { ruleId: "SE-P-124", pattern: String.raw`(--address=0\.0\.0\.0|-S\s+0\.0\.0\.0:|--bind=0\.0\.0\.0|--listen=0\.0\.0\.0|kubectl\s+proxy\s+--address=0\.0\.0\.0)`, failureFamily: "F5", confidence: 0.75, provenanceTier: "gtfobins", mitreTechniques: ["T1090.001"], description: "server listen on 0.0.0.0 all-interfaces" },
  { ruleId: "SE-P-125", pattern: String.raw`\bfinger\s+[a-zA-Z_][\w]*@[\w.-]+\b`, failureFamily: "F4", confidence: 0.7, provenanceTier: "gtfobins", mitreTechniques: ["T1071.001"], description: "finger remote exfil pattern" },

  // GTFOBins — interpreter file-write primitives
  { ruleId: "SE-P-126", pattern: String.raw`\b(node|ruby|lua|python[23]?|perl|elvish|jrunscript|julia)\s+-[eEr]\s+['"][^'"]*(writeFileSync|File\.open\s*\([^)]*,\s*['"]w|io\.open\s*\([^)]*,\s*['"]w|FileWriter|open\s*\([^)]*,\s*['"]w)`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1105", "T1059.006"], description: "interpreter inline file-write primitive" },
  { ruleId: "SE-P-127", pattern: String.raw`\bgdb\s+[^|]*-ex\s+['"]dump\s+(value|binary|memory)\b`, failureFamily: "F4", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1005"], description: "gdb dump value (memory exfil)" },
  { ruleId: "SE-P-128", pattern: String.raw`\bcpio\s+(-[a-z]*p[a-z]*\b|--pass-through)`, failureFamily: "F4", confidence: 0.75, provenanceTier: "gtfobins", mitreTechniques: ["T1105"], description: "cpio pass-through write" },
  { ruleId: "SE-P-129", pattern: String.raw`\bcurl\s+[^|]*file://[^\s]+\s+[^|]*-o\s+/(tmp|home|var/tmp|root)/`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1005"], description: "curl file:// + -o to writable dir" },
  { ruleId: "SE-P-130", pattern: String.raw`\b(rpm\s+-[Uivh]{1,3}\b[^|]*\.rpm|yum\s+localinstall\b|dnf\s+localinstall\b|pkg\s+install\s+[^|]*\./\S+\.(txz|pkg)|snap\s+install\b[^|]*--dangerous\b)`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1546.016", "T1204.002"], description: "local-file package install (arbitrary script)" },

  // GTFOBins — command-execution-via-option / config
  { ruleId: "SE-P-131", pattern: String.raw`\besyscmd\s*\(|\bsyscmd\s*\(`, failureFamily: "F4", confidence: 0.9, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "m4 esyscmd/syscmd builtin" },
  { ruleId: "SE-P-132", pattern: String.raw`--on-download-complete=\S+`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "aria2c/wget on-download-complete handler" },
  { ruleId: "SE-P-133", pattern: String.raw`--(conf-script|exec-config|script-file)=['"]?\S*sh\b|\bdnsmasq\s+[^|]*--conf-script=`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "--conf-script= invokes external script" },
  { ruleId: "SE-P-134", pattern: String.raw`\bnohup\s+/(path/to|tmp|var/tmp|home/[^/]+/\.)\S+`, failureFamily: "F4", confidence: 0.7, provenanceTier: "gtfobins", mitreTechniques: ["T1059.004"], description: "nohup executing writable-dir binary" },
  { ruleId: "SE-P-135", pattern: String.raw`\\verbatiminput\s*\{\s*/(etc|root|home)/|\\input\s*\{\s*/(etc|root)/`, failureFamily: "F3", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1552.001"], description: "LaTeX \\verbatiminput of system file" },
  { ruleId: "SE-P-136", pattern: String.raw`\b(jjs|jrunscript)\s+[^|]*-e\s+['"][^'"]*(Java\.type\s*\(['"]java\.(net|io|lang\.ProcessBuilder))`, failureFamily: "F4", confidence: 0.85, provenanceTier: "gtfobins", mitreTechniques: ["T1059.006", "T1105"], description: "jjs/jrunscript Java network or process primitive" },

  // Command injection — eval/exec on positional/user-input var
  { ruleId: "SE-P-137", pattern: String.raw`\beval\s+["']?\$\{?[1-9@*#]`, failureFamily: "F2", confidence: 0.9, provenanceTier: "manual", mitreTechniques: ["T1059.004"], description: "eval of positional parameter (command injection)" },
  { ruleId: "SE-P-138", pattern: String.raw`\beval\s+["']?\$\{?(input|user|arg|cmd|query|param)\w*`, failureFamily: "F2", confidence: 0.75, provenanceTier: "manual", mitreTechniques: ["T1059.004"], description: "eval of user-named variable (command injection)" },
  { ruleId: "SE-P-139", pattern: String.raw`\b(rm|dd|shred|truncate|unlink)\s+[^|;&\n]{0,60}?["']?/usr/(?!local/)\S+`, failureFamily: "F1", confidence: 0.85, provenanceTier: "manual", mitreTechniques: ["T1485"], description: "destructive op on /usr/ system path" },
];

export const PROVENANCE_TIER_WEIGHT: Record<string, number> = {
  mitre: 1.0,
  cve: 0.9,
  gtfobins: 0.85,
  shellcheck: 0.8,
  owasp: 0.8,
  manual: 0.6,
};

interface CompiledRule {
  regex: RegExp;
  spec: RuleSpec;
}

const compiledRules: CompiledRule[] = RULES.map((spec) => ({
  regex: new RegExp(spec.pattern, "i"),
  spec,
}));

export function detectPatterns(cmd: string): { score: number; matches: FiredRule[] } {
  const matches: FiredRule[] = [];
  let best = 0;
  for (const { regex, spec } of compiledRules) {
    if (!regex.test(cmd)) continue;
    const pw = PROVENANCE_TIER_WEIGHT[spec.provenanceTier] ?? 0.6;
    const effective = pw * spec.confidence;
    matches.push({
      ruleId: spec.ruleId,
      failureFamily: spec.failureFamily,
      confidence: spec.confidence,
      provenanceTier: spec.provenanceTier,
      provenanceWeight: pw,
      effectiveScore: effective,
      description: spec.description,
    });
    if (effective > best) best = effective;
  }
  return { score: best, matches };
}
