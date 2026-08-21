import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { createServer as createNetServer, connect } from "node:net";
import type { AddressInfo } from "node:net";
import { NetworkPolicy } from "../lib/netpolicy.ts";
import { startProxies } from "../lib/netproxy.ts";

/** Tiny SOCKS5 CONNECT client used to exercise the SOCKS proxy. */
function socks5Connect(
  port: number,
  targetHost: string,
  targetPort: number,
): Promise<{ reply: number; socket: import("node:net").Socket }> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    let state: "greet" | "req" | "done" = "greet";
    let buf = Buffer.alloc(0);
    socket.on("connect", () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no auth
    });
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (state === "greet" && buf.length >= 2) {
        assert.equal(buf[1], 0x00); // server accepted no-auth
        buf = Buffer.alloc(0);
        state = "req";
        // CONNECT request
        const hostBuf = Buffer.from(targetHost, "utf8");
        const req = Buffer.alloc(4 + 1 + hostBuf.length + 2);
        req[0] = 0x05;
        req[1] = 0x01; // CONNECT
        req[2] = 0x00;
        req[3] = 0x03; // domain
        req[4] = hostBuf.length;
        hostBuf.copy(req, 5);
        req.writeUInt16BE(targetPort, 5 + hostBuf.length);
        socket.write(req);
      } else if (state === "req" && buf.length >= 2) {
        // success reply is 10 bytes with status 0x00; error replies are 2
        // bytes with a non-zero status. Resolve as soon as the status byte
        // is decisive either way.
        const status = buf.readUInt8(1);
        if (status !== 0x00 || buf.length >= 10) {
          resolve({ reply: status, socket });
          state = "done";
        }
      }
    });
    socket.on("error", reject);
  });
}

test("proxies: HTTP CONNECT allow/deny + plain forward + SOCKS5", async () => {
  // Target server (would be the "outside" world)
  const target = createHttpServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("target-ok");
  });
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
  const targetPort = (target.address() as AddressInfo).port;

  const asks: string[] = [];
  const policy = new NetworkPolicy(
    ["127.0.0.1", "allowed.example.com"],
    ["denied.example.com"],
    async (host, port) => {
      asks.push(`${host}:${port}`);
      return false; // human says no in tests
    },
  );
  const proxies = await startProxies(policy);

  try {
    // --- HTTP CONNECT to an allowed host (127.0.0.1) ---
    const tunnel = await new Promise<{ socket: import("node:net").Socket }>((resolve, reject) => {
      const socket = connect(proxies.httpPort, "127.0.0.1", () => {
        socket.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
      });
      let buf = "";
      let sent = false;
      socket.on("data", (chunk: Buffer) => {
        buf += chunk.toString();
        if (!sent && buf.includes("\r\n\r\n")) {
          sent = true;
          assert.match(buf, /200 Connection Established/);
          // send an HTTP request through the tunnel
          socket.write(`GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
          resolve({ socket });
        }
      });
      socket.on("error", reject);
    });
    let got = "";
    await new Promise<void>((resolve) => {
      tunnel.socket.on("data", (c: Buffer) => (got += c.toString()));
      tunnel.socket.on("close", () => resolve());
    });
    assert.match(got, /target-ok/);
    tunnel.socket.destroy();

    // --- HTTP CONNECT to a denied host ---
    const deniedStatus = await new Promise<string>((resolve, reject) => {
      const socket = connect(proxies.httpPort, "127.0.0.1", () => {
        socket.write(`CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com\r\n\r\n`);
      });
      let buf = "";
      socket.on("data", (c: Buffer) => {
        buf += c.toString();
        if (buf.includes("\r\n")) resolve(buf.split("\r\n")[0] ?? "closed");
      });
      socket.on("error", reject);
      socket.on("close", () => resolve("closed"));
    });
    assert.equal(deniedStatus, "HTTP/1.1 403 Forbidden");

    // --- Plain HTTP through the proxy ---
    const plain = await new Promise<string>((resolve, reject) => {
      const socket = connect(proxies.httpPort, "127.0.0.1", () => {
        socket.write(`GET http://127.0.0.1:${targetPort}/ HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`);
      });
      let buf = "";
      socket.on("data", (c: Buffer) => (buf += c.toString()));
      socket.on("close", () => resolve(buf));
      socket.on("error", reject);
    });
    assert.match(plain, /HTTP\/1\.1 200/);
    assert.match(plain, /target-ok/);

    // --- SOCKS5 CONNECT to an allowed host ---
    const socks = await socks5Connect(proxies.socksPort, "127.0.0.1", targetPort);
    assert.equal(socks.reply, 0x00); // success
    let got2 = "";
    await new Promise<void>((resolve) => {
      socks.socket.on("data", (c: Buffer) => (got2 += c.toString()));
      socks.socket.write(`GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      socks.socket.on("close", () => resolve());
    });
    assert.match(got2, /target-ok/);
    socks.socket.destroy();

    // --- SOCKS5 CONNECT to a host the human denied (ask → false) ---
    const socksDenied = await socks5Connect(proxies.socksPort, "notallowed.example.com", 443);
    assert.equal(socksDenied.reply, 0x02); // connection not allowed
    socksDenied.socket.destroy();
    assert.deepEqual(asks, ["notallowed.example.com:443"]);
  } finally {
    proxies.close();
    target.close();
  }
});
