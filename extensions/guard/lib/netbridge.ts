/**
 * socat bridges connecting the sandbox to the host proxies.
 *
 * Architecture (mirrors anthropic-experimental/sandbox-runtime):
 *  - Host side: one socat per proxy, `UNIX-LISTEN:<sock> TCP:127.0.0.1:<port>`,
 *    so the sandbox reaches the proxies over Unix sockets.
 *  - The socket files are `--bind` (read-write) into the bwrap sandbox —
 *    `connect()` on a socket needs write permission on the inode, so a
 *    read-only bind would fail.
 *  - Sandbox side: `socat TCP-LISTEN:3128 UNIX-CONNECT:<sock>` etc., so the
 *    standard proxy env vars (`HTTP_PROXY=http://127.0.0.1:3128`) work.
 *
 * Sockets live under ~/.cache/guard/net/<random>/ and are cleaned up with
 * the bridge. If socat is missing the bridge fails closed: the sandbox still
 * gets `--unshare-net` (no egress at all) rather than bypassing the policy.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { quote } from "shell-quote";

export interface NetBridge {
  httpSocketPath: string;
  socksSocketPath: string;
  httpProxyPort: number;
  socksProxyPort: number;
  dir: string;
  processes: ChildProcess[];
}

export const SANDBOX_HTTP_PORT = 3128;
export const SANDBOX_SOCKS_PORT = 1080;

const SOCKET_READY_TIMEOUT_MS = 8000;

/**
 * Remove bridge dirs left behind by crashed pi processes. Each dir records
 * the socat PIDs that own it; when all of them are dead the bridges are
 * useless (their host proxies died with pi) and can be swept. Safe under
 * concurrent pi instances: a live instance's dir has live socat PIDs.
 */
export function sweepStaleBridges(): void {
  const base = join(homedir(), ".cache", "guard", "net");
  let dirs: string[] = [];
  try {
    dirs = readdirSync(base);
  } catch {
    return; // no net dir yet
  }
  for (const name of dirs) {
    const dir = join(base, name);
    let pids: number[] = [];
    try {
      pids = readFileSync(join(dir, "pids"), "utf8")
        .split("\n")
        .map((line) => Number(line.trim()))
        .filter((pid) => pid > 0);
    } catch {
      continue; // no pid file — not ours to judge
    }
    if (pids.length === 0) continue;
    const anyAlive = pids.some((pid) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    });
    if (!anyAlive) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
  }
}

export async function startBridge(proxyPorts: {
  httpPort: number;
  socksPort: number;
}): Promise<NetBridge> {
  sweepStaleBridges();
  const dir = join(homedir(), ".cache", "guard", "net", randomBytes(8).toString("hex"));
  mkdirSync(dir, { recursive: true });
  const httpSocketPath = join(dir, "http.sock");
  const socksSocketPath = join(dir, "socks.sock");

  const procs: ChildProcess[] = [];
  const pairs: Array<[string, number]> = [
    [httpSocketPath, proxyPorts.httpPort],
    [socksSocketPath, proxyPorts.socksPort],
  ];
  for (const [sock, port] of pairs) {
    procs.push(
      spawn(
        "socat",
        [`UNIX-LISTEN:${sock},fork,reuseaddr`, `TCP:127.0.0.1:${port}`],
        { stdio: "ignore" },
      ),
    );
  }
  // Record the socat PIDs so a later instance can sweep this dir if pi crashed.
  try {
    writeFileSync(join(dir, "pids"), procs.map((p) => p.pid ?? 0).filter((pid) => pid > 0).join("\n") + "\n");
  } catch {
    /* best effort */
  }

  const deadline = Date.now() + SOCKET_READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (existsSync(httpSocketPath) && existsSync(socksSocketPath)) {
      return {
        httpSocketPath,
        socksSocketPath,
        httpProxyPort: proxyPorts.httpPort,
        socksProxyPort: proxyPorts.socksPort,
        dir,
        processes: procs,
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  // Timed out (e.g. socat not installed) — clean up and fail closed.
  for (const p of procs) {
    try {
      p.kill("SIGTERM");
    } catch {
      /* already gone */
    }
  }
  rmSync(dir, { recursive: true, force: true });
  throw new Error("socat bridge failed to create sockets (is socat installed?)");
}

export function stopBridge(bridge: NetBridge | null): void {
  if (!bridge) return;
  for (const p of bridge.processes) {
    try {
      p.kill("SIGTERM");
    } catch {
      /* already gone */
    }
  }
  try {
    rmSync(bridge.dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

/** Proxy env vars set inside the sandbox (mirrors srt's generateProxyEnvVars). */
export function buildNetEnvVars(): Array<[string, string]> {
  const noProxy = [
    "localhost",
    "127.0.0.1",
    "::1",
    "169.254.0.0/16", // link-local
    "10.0.0.0/8", // private
    "172.16.0.0/12", // private
    "192.168.0.0/16", // private
  ].join(",");
  const httpUrl = `http://127.0.0.1:${SANDBOX_HTTP_PORT}`;
  const socksUrl = `socks5h://127.0.0.1:${SANDBOX_SOCKS_PORT}`;
  return [
    ["HTTP_PROXY", httpUrl],
    ["http_proxy", httpUrl],
    ["HTTPS_PROXY", httpUrl],
    ["https_proxy", httpUrl],
    // Prefer the HTTP URL over socks5h: Python httpx eagerly imports socksio
    // when ALL_PROXY is a socks5h:// URL and crashes before any bytes flow.
    ["ALL_PROXY", httpUrl],
    ["all_proxy", httpUrl],
    ["GRPC_PROXY", httpUrl],
    ["grpc_proxy", httpUrl],
    ["FTP_PROXY", socksUrl],
    ["ftp_proxy", socksUrl],
    ["NO_PROXY", noProxy],
    ["no_proxy", noProxy],
    // git-over-ssh: route ssh's TCP stream through the in-sandbox HTTP
    // listener as an HTTP CONNECT. ControlMaster/ControlPath are disabled —
    // ssh connection multiplexing breaks inside the sandbox (mux sockets
    // under ~/.ssh are not reachable).
    [
      "GIT_SSH_COMMAND",
      `ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand='socat - PROXY:127.0.0.1:%h:%p,proxyport=${SANDBOX_HTTP_PORT}'`,
    ],
  ];
}

/** Script that starts the in-sandbox proxy listeners, then runs the command. */
export function buildSandboxNetCommand(command: string, bridge: NetBridge): string {
  const lines = [
    `socat TCP-LISTEN:${SANDBOX_HTTP_PORT},fork,reuseaddr UNIX-CONNECT:${quote([bridge.httpSocketPath])} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:${SANDBOX_SOCKS_PORT},fork,reuseaddr UNIX-CONNECT:${quote([bridge.socksSocketPath])} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ];
  return [...lines, `eval ${quote([command])}`].join("\n");
}
