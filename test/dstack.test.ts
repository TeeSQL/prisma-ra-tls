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

const VALID_RESPONSE = JSON.stringify({ key: "-----BEGIN KEY-----", cert: "-----BEGIN CERT-----" });

function emitSuccessfulResponse(body: string = VALID_RESPONSE): void {
  mockSocket.emit("connect");
  mockSocket.emit("data", Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`));
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
    emitSuccessfulResponse();
    await promise;
    expect(createConnection).toHaveBeenCalledWith("/var/run/dstack.sock");
  });

  it("connects to a custom socket path", async () => {
    const promise = getDstackClientCert("/custom/dstack.sock");
    emitSuccessfulResponse();
    await promise;
    expect(createConnection).toHaveBeenCalledWith("/custom/dstack.sock");
  });

  it("returns key and cert buffers on success", async () => {
    const promise = getDstackClientCert();
    emitSuccessfulResponse();
    const { key, cert } = await promise;
    expect(key.toString()).toBe("-----BEGIN KEY-----");
    expect(cert.toString()).toBe("-----BEGIN CERT-----");
  });

  it("writes an HTTP POST to the socket on connect", async () => {
    const promise = getDstackClientCert();
    emitSuccessfulResponse();
    await promise;
    expect(mockSocket.written[0]).toContain("POST /GetTlsKey HTTP/1.1");
    expect(mockSocket.written[0]).toContain("Content-Type: application/json");
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
    const full = `HTTP/1.1 200 OK\r\n\r\n${VALID_RESPONSE}`;
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
        json: async () => ({ key: "sim-key", cert: "sim-cert" }),
      })
    );
    const { key, cert } = await getDstackClientCert();
    expect(key.toString()).toBe("sim-key");
    expect(cert.toString()).toBe("sim-cert");
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
});
