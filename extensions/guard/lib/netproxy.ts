/**
 * Host-side network proxies enforcing the guard's whitelist policy.
 *
 * Two proxies share one {@link NetworkPolicy}:
 *  - HTTP proxy (node:http): plain-HTTP forwarding plus `CONNECT` tunneling
 *    (HTTPS and any CONNECT-capable protocol).
 *  - SOCKS5 proxy (node:net): `CONNECT` command only (BIND/UDP ASSOCIATE are
 *    refused), for tools that speak SOCKS directly (curl --socks5, ssh
 *    ProxyCommand, ftp, …).
 *
 * The sandbox has no network interfaces (`--unshare-net`), so every egress
 * must arrive here — through socat bridges wired from Unix sockets bound
 * into the sandbox. The proxies run on 127.0.0.1 with ephemeral ports and
 * only ever answer connections from the same user.
 */

import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer as createNetServer, connect as tcpConnect } from "node:net";
import type { Socket } from "node:net";
import type { Duplex } from "node:stream";
import { request as httpRequest } from "node:http";
import type { NetworkPolicy } from "./netpolicy.ts";

export interface ProxyPair {
  httpPort: number;
  socksPort: number;
  close(): void;
}

function parseHostPort(hostPort: string, defaultPort: number): { host: string; port: number } {
  const idx = hostPort.lastIndexOf(":");
  if (idx === -1) return { host: hostPort, port: defaultPort };
  const host = hostPort.slice(0, idx);
  const port = Number(hostPort.slice(idx + 1));
  return Number.isInteger(port) && port > 0 && port < 65536
    ? { host, port }
    : { host, port: defaultPort };
}

export async function startProxies(policy: NetworkPolicy): Promise<ProxyPair> {
  const httpServer = createHttpServer((req, res) => {
    void handlePlainHttp(policy, req, res);
  });
  httpServer.on("connect", (req, client, head) => {
    void handleConnect(policy, req.url ?? "", client, head);
  });

  const socksServer = createNetServer((socket) => {
    void handleSocks(policy, socket);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    httpServer.once("error", onError);
    socksServer.once("error", onError);
    httpServer.listen(0, "127.0.0.1", () => {
      socksServer.listen(0, "127.0.0.1", () => {
        httpServer.off("error", onError);
        socksServer.off("error", onError);
        resolve();
      });
    });
  });

  const httpAddr = httpServer.address();
  const socksAddr = socksServer.address();
  if (
    !httpAddr || typeof httpAddr === "string" ||
    !socksAddr || typeof socksAddr === "string"
  ) {
    httpServer.close();
    socksServer.close();
    throw new Error("proxy listen failed");
  }

  return {
    httpPort: httpAddr.port,
    socksPort: socksAddr.port,
    close() {
      httpServer.close();
      socksServer.close();
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP proxy
// ---------------------------------------------------------------------------

async function handleConnect(
  policy: NetworkPolicy,
  target: string,
  client: Duplex,
  head: Buffer,
): Promise<void> {
  const { host, port } = parseHostPort(target, 443);
  if (!(await policy.decide(host, port))) {
    client.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    return;
  }
  const upstream = tcpConnect({ host, port });
  upstream.on("connect", () => {
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length > 0) upstream.write(head);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  upstream.on("error", () => client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
  client.on("error", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  client.on("close", () => upstream.destroy());
}

async function handlePlainHttp(
  policy: NetworkPolicy,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // Proxy requests arrive in absolute-form: GET http://host:port/path.
  let url: URL | null = null;
  try {
    url = new URL(req.url ?? "");
  } catch {
    url = null;
  }

  let host: string;
  let port: number;
  let path: string;
  if (url && (url.protocol === "http:" || url.protocol === "https:")) {
    host = url.hostname;
    port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    path = url.pathname + url.search;
  } else if (req.headers.host) {
    const h = parseHostPort(req.headers.host, 80);
    host = h.host;
    port = h.port;
    path = req.url ?? "/";
  } else {
    res.writeHead(400, "missing host").end("missing host header");
    return;
  }

  if (url?.protocol === "https:") {
    // Absolute-form https in a plain request is rare (clients use CONNECT).
    // Tunnel it the same way as CONNECT.
    if (!(await policy.decide(host, port))) {
      res.writeHead(403).end("host not allowed");
      return;
    }
    const upstream = tcpConnect({ host, port });
    upstream.on("connect", () => {
      res.writeHead(200, "Connection Established");
      res.flushHeaders();
      req.socket.pipe(upstream);
      upstream.pipe(req.socket);
    });
    upstream.on("error", () => res.destroy());
    req.on("error", () => upstream.destroy());
    return;
  }

  if (!(await policy.decide(host, port))) {
    res.writeHead(403, "host not allowed").end("host not allowed");
    return;
  }

  const upstream = httpRequest({
    host,
    port,
    path,
    method: req.method ?? "GET",
    headers: { ...req.headers, host: req.headers.host ?? host },
  });
  upstream.on("response", (upRes) => {
    res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage ?? "", upRes.headers);
    upRes.pipe(res);
  });
  upstream.on("error", () => {
    if (!res.headersSent) res.writeHead(502).end("proxy upstream error");
    else res.destroy();
  });
  req.on("error", () => upstream.destroy());
  req.pipe(upstream);
}

// ---------------------------------------------------------------------------
// SOCKS5 proxy
// ---------------------------------------------------------------------------

async function handleSocks(policy: NetworkPolicy, socket: Socket): Promise<void> {
  let buf = Buffer.alloc(0);
  let greeted = false;
  let connected = false;

  socket.on("data", (chunk: Buffer) => {
    // Once the tunnel is established the data handler must stop parsing —
    // the socket is piped to the upstream and its bytes are tunnel data, not
    // SOCKS frames.
    if (connected) return;
    buf = Buffer.concat([buf, chunk]);

    if (!greeted) {
      if (buf.length < 2) return;
      const nMethods = buf.readUInt8(1);
      if (buf.length < 2 + nMethods) return;
      socket.write(Buffer.from([0x05, 0x00])); // no auth
      buf = buf.subarray(2 + nMethods);
      greeted = true;
    }

    if (buf.length < 4) return;
    const cmd = buf[1];
    const atyp = buf[3];

    let addrLen: number;
    let addr: string;
    if (atyp === 1) {
      addrLen = 4;
      addr = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
    } else if (atyp === 3) {
      if (buf.length < 5) return;
      const len = buf.readUInt8(4);
      addrLen = 1 + len;
      if (buf.length < 4 + addrLen) return;
      addr = buf.subarray(5, 5 + len).toString("utf8");
    } else if (atyp === 4) {
      addrLen = 16;
      if (buf.length < 4 + addrLen) return;
      const groups: string[] = [];
      for (let i = 0; i < 8; i++) {
        groups.push(buf.readUInt16BE(4 + i * 2).toString(16));
      }
      addr = groups.join(":");
    } else {
      socket.end(Buffer.from([0x05, 0x08])); // address type not supported
      return;
    }

    const need = 4 + addrLen + 2;
    if (buf.length < need) return;
    const port = buf.readUInt16BE(4 + addrLen);
    buf = buf.subarray(need);

    if (cmd !== 0x01) {
      socket.end(Buffer.from([0x05, 0x07])); // command not supported
      return;
    }

    void (async () => {
      if (!(await policy.decide(addr, port))) {
        socket.end(Buffer.from([0x05, 0x02])); // connection not allowed
        return;
      }
      const upstream = tcpConnect({ host: addr, port });
      upstream.on("connect", () => {
        connected = true;
        // reply success with BND.ADDR 0.0.0.0:0
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      upstream.on("error", () => socket.end(Buffer.from([0x05, 0x05]))); // refused
      socket.on("error", () => upstream.destroy());
      upstream.on("close", () => socket.destroy());
      socket.on("close", () => upstream.destroy());
    })();
  });

  socket.on("error", () => {
    socket.destroy();
  });
}
