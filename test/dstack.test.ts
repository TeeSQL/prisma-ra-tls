import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

// ---------------------------------------------------------------------------
// Mock the `net` module before importing getDstackClientCert
// ---------------------------------------------------------------------------

class MockSocket extends EventEmitter {
  public written: string[] = [];
  private timeoutCb?: () => void;

  write(data: string): boolean {
    this.written.push(data);
    return true;
  }

  setTimeout(_ms: number, cb: () => void): this {
    this.timeoutCb = cb;
    return this;
  }

  destroy(): this {
    return this;
  }

  triggerTimeout(): void {
    this.timeoutCb?.();
  }
}

let mockSocket: MockSocket;

vi.mock("net", () => ({
  createConnection: vi.fn().mockImplementation(() => {
    mockSocket = new MockSocket();
    return mockSocket;
  }),
}));

import { getDstackClientCert } from "../src/dstack.js";
import { createConnection } from "net";

const LEAF_PEM = "-----BEGIN LEAF-----";
const INTERMEDIATE_PEM = "-----BEGIN INTER-----";
const CHAIN_RESPONSE = JSON.stringify({
  key: "-----BEGIN KEY-----",
  certificate_chain: [LEAF_PEM, INTERMEDIATE_PEM],
});
const LEGACY_RESPONSE = JSON.stringify({
  key: "-----BEGIN KEY-----",
  cert: "-----BEGIN CERT-----",
});

function emitResponse(body: string): void {
  mockSocket.emit("connect");
  mockSocket.emit(
    "data",
    Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`)
  );
  mockSocket.emit("end");
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env["DSTACK_SIMULATOR_ENDPOINT"];
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env["DSTACK_SIMULATOR_ENDPOINT"];
});

// ---------------------------------------------------------------------------
// Socket path
// ---------------------------------------------------------------------------

describe("getDstackClientCert — Unix socket", () => {
  it("connects to the default socket path", async () => {
    const promise = getDstackClientCert();
    emitResponse(CHAIN_RESPONSE);
    await promise;
    expect(createConnection).toHaveBeenCalledWith("/var/run/dstack.sock");
  });

  it("connects to a custom socket path", async () => {
    const promise = getDstackClientCert("/custom/dstack.sock");
    emitResponse(CHAIN_RESPONSE);
    await promise;
    expect(createConnection).toHaveBeenCalledWith("/custom/dstack.sock");
  });

  it("returns key, leaf cert, and joined chain on success", async () => {
    const promise = getDstackClientCert();
    emitResponse(CHAIN_RESPONSE);
    const { key, cert, certChainPem } = await promise;
    expect(key.toString()).toBe("-----BEGIN KEY-----");
    expect(cert.toString()).toBe(LEAF_PEM);
    expect(certChainPem).toContain(LEAF_PEM);
    expect(certChainPem).toContain(INTERMEDIATE_PEM);
    expect(certChainPem.endsWith("\n")).toBe(true);
  });

  it("falls back to legacy `cert` field when certificate_chain absent", async () => {
    const promise = getDstackClientCert();
    emitResponse(LEGACY_RESPONSE);
    const { key, cert, certChainPem } = await promise;
    expect(key.toString()).toBe("-----BEGIN KEY-----");
    expect(cert.toString()).toBe("-----BEGIN CERT-----");
    expect(certChainPem.endsWith("\n")).toBe(true);
  });

  it("rejects when both certificate_chain and cert are missing", async () => {
    const promise = getDstackClientCert();
    emitResponse(JSON.stringify({ key: "k" }));
    await expect(promise).rejects.toThrow("missing certificate_chain");
  });

  it("preserves trailing newline in chain when last cert already ends with one", async () => {
    const promise = getDstackClientCert();
    const body = JSON.stringify({
      key: "k",
      certificate_chain: ["leaf\n", "intermediate\n"],
    });
    emitResponse(body);
    const { certChainPem } = await promise;
    // chain.join("\n") on ["leaf\n", "intermediate\n"] yields
    // "leaf\n\nintermediate\n" which already ends with "\n", so the
    // "already ends with newline" branch returns it as-is.
    expect(certChainPem).toBe("leaf\n\nintermediate\n");
  });

  it("preserves trailing newline in legacy cert PEM when present", async () => {
    const promise = getDstackClientCert();
    emitResponse(JSON.stringify({ key: "k", cert: "single-cert\n" }));
    const { certChainPem } = await promise;
    expect(certChainPem).toBe("single-cert\n");
  });

  it("writes an HTTP POST to the socket on connect", async () => {
    const promise = getDstackClientCert();
    emitResponse(CHAIN_RESPONSE);
    await promise;
    expect(mockSocket.written[0]).toContain("POST /GetTlsKey HTTP/1.1");
    expect(mockSocket.written[0]).toContain("Content-Type: application/json");
  });

  it("sends usage_ra_tls/server_auth/client_auth flags", async () => {
    const promise = getDstackClientCert(undefined, {
      usageRaTls: true,
      usageClientAuth: true,
    });
    emitResponse(CHAIN_RESPONSE);
    await promise;
    const written = mockSocket.written[0] ?? "";
    const sep = written.indexOf("\r\n\r\n");
    const body = written.slice(sep + 4);
    const parsed = JSON.parse(body);
    expect(parsed.usage_ra_tls).toBe(true);
    expect(parsed.usage_client_auth).toBe(true);
    expect(parsed.usage_server_auth).toBe(true);
  });

  it("includes alt_names when provided", async () => {
    const promise = getDstackClientCert(undefined, {
      altNames: ["foo", "bar"],
    });
    emitResponse(CHAIN_RESPONSE);
    await promise;
    const written = mockSocket.written[0] ?? "";
    const sep = written.indexOf("\r\n\r\n");
    const parsed = JSON.parse(written.slice(sep + 4));
    expect(parsed.alt_names).toEqual(["foo", "bar"]);
  });

  it("rejects when response has no \\r\\n\\r\\n separator (malformed HTTP)", async () => {
    const promise = getDstackClientCert();
    mockSocket.emit("connect");
    mockSocket.emit("data", Buffer.from("not-http-at-all"));
    mockSocket.emit("end");
    await expect(promise).rejects.toThrow("malformed HTTP response");
  });

  it("rejects when response body is not valid JSON", async () => {
    const promise = getDstackClientCert();
    mockSocket.emit("connect");
    mockSocket.emit("data", Buffer.from("HTTP/1.1 200 OK\r\n\r\nnot-json{{{"));
    mockSocket.emit("end");
    await expect(promise).rejects.toThrow("failed to parse response");
  });

  it("rejects on socket error", async () => {
    const promise = getDstackClientCert();
    mockSocket.emit("error", new Error("ENOENT: no such file"));
    await expect(promise).rejects.toThrow("ENOENT: no such file");
    await expect(promise).rejects.toThrow("dstack CVM");
  });

  it("rejects on timeout", async () => {
    const promise = getDstackClientCert();
    mockSocket.triggerTimeout();
    await expect(promise).rejects.toThrow("timed out");
  });

  it("accumulates data across multiple chunks", async () => {
    const promise = getDstackClientCert();
    const full = `HTTP/1.1 200 OK\r\n\r\n${CHAIN_RESPONSE}`;
    mockSocket.emit("connect");
    mockSocket.emit("data", Buffer.from(full.slice(0, 10)));
    mockSocket.emit("data", Buffer.from(full.slice(10)));
    mockSocket.emit("end");
    const { key } = await promise;
    expect(key.toString()).toBe("-----BEGIN KEY-----");
  });
});

// ---------------------------------------------------------------------------
// Simulator endpoint
// ---------------------------------------------------------------------------

describe("getDstackClientCert — simulator", () => {
  it("uses fetch against DSTACK_SIMULATOR_ENDPOINT when set", async () => {
    process.env["DSTACK_SIMULATOR_ENDPOINT"] = "http://localhost:8090";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          key: "sim-key",
          certificate_chain: ["sim-leaf", "sim-inter"],
        }),
      })
    );
    const { key, cert } = await getDstackClientCert();
    expect(key.toString()).toBe("sim-key");
    expect(cert.toString()).toBe("sim-leaf");
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      "http://localhost:8090/GetTlsKey",
      expect.anything()
    );
    // createConnection should NOT have been called
    expect(createConnection).not.toHaveBeenCalled();
  });

  it("throws when simulator returns non-ok status", async () => {
    process.env["DSTACK_SIMULATOR_ENDPOINT"] = "http://localhost:8090";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 500 })
    );
    await expect(getDstackClientCert()).rejects.toThrow("500");
  });

  it("simulator falls back to legacy cert field", async () => {
    process.env["DSTACK_SIMULATOR_ENDPOINT"] = "http://localhost:8090";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ key: "sim-key", cert: "sim-leaf" }),
      })
    );
    const { cert } = await getDstackClientCert();
    expect(cert.toString()).toBe("sim-leaf");
  });
});
