import { describe, it, expect, vi, beforeEach } from "vitest";
import tls from "tls";

// ---------------------------------------------------------------------------
// Mock pg before importing RaTlsPool
// ---------------------------------------------------------------------------

const mockSuperConnect = vi.fn();

vi.mock("pg", () => ({
  default: {
    Pool: class MockPool {
      async connect() {
        return mockSuperConnect();
      }
    },
  },
}));

// Mock extractTdxQuote so we don't need real certs
vi.mock("../src/cert.js", () => ({
  extractTdxQuote: vi.fn(),
}));

import { RaTlsPool } from "../src/pool.js";
import { extractTdxQuote } from "../src/cert.js";
import { NoopVerifier } from "../src/verifiers/noop.js";
import type { RaTlsOptions } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_CERT_DER = Buffer.alloc(64, 0xaa);
const FAKE_QUOTE = Buffer.alloc(32, 0xbb);

function makeTlsSocket(certRaw: Buffer | null = FAKE_CERT_DER): object {
  const socket = Object.create(tls.TLSSocket.prototype) as tls.TLSSocket;
  (socket as unknown as Record<string, unknown>).getPeerCertificate = vi
    .fn()
    .mockReturnValue(certRaw ? { raw: certRaw } : {});
  return socket;
}

function makeClient(stream?: object): Record<string, unknown> {
  return {
    connection: { stream },
    release: vi.fn(),
  };
}

function makePool(opts: Partial<RaTlsOptions> = {}): RaTlsPool {
  return new RaTlsPool({ connectionString: "postgresql://localhost/test" }, {
    verifier: new NoopVerifier(),
    ...opts,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(extractTdxQuote).mockReturnValue(FAKE_QUOTE);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RaTlsPool.connect", () => {
  it("returns the client when attestation succeeds", async () => {
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool();
    const result = await pool.connect();
    expect(result).toBe(client);
  });

  it("passes when stream is not a TLS socket (plain connection)", async () => {
    const client = makeClient({ notATlsSocket: true });
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool();
    await expect(pool.connect()).resolves.toBe(client);
    expect(extractTdxQuote).not.toHaveBeenCalled();
  });

  it("passes when connection object has no stream", async () => {
    const client = makeClient(undefined);
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool();
    await expect(pool.connect()).resolves.toBe(client);
  });

  it("passes when peer certificate has no raw field", async () => {
    const socket = Object.create(tls.TLSSocket.prototype) as tls.TLSSocket;
    (socket as unknown as Record<string, unknown>).getPeerCertificate = vi
      .fn()
      .mockReturnValue({}); // no .raw
    const client = makeClient(socket);
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool();
    await expect(pool.connect()).resolves.toBe(client);
  });

  it("uses cache: skips re-verification for the same cert fingerprint", async () => {
    const socket = makeTlsSocket();
    const client = makeClient(socket);
    mockSuperConnect.mockResolvedValue(client);
    const verifier = { verify: vi.fn().mockResolvedValue({ tcbStatus: "UpToDate", isDebugMode: false, mrTd: "", rtmr0: "", rtmr1: "", rtmr2: "", rtmr3: "" }) };
    const pool = makePool({ verifier });

    await pool.connect();
    await pool.connect();

    // verifier.verify should only be called once despite two connects
    expect(verifier.verify).toHaveBeenCalledTimes(1);
  });

  it("re-verifies after cache TTL expires", async () => {
    vi.useFakeTimers();
    const socket = makeTlsSocket();
    const client = makeClient(socket);
    mockSuperConnect.mockResolvedValue(client);
    const verifier = { verify: vi.fn().mockResolvedValue({ tcbStatus: "UpToDate", isDebugMode: false, mrTd: "", rtmr0: "", rtmr1: "", rtmr2: "", rtmr3: "" }) };
    const pool = makePool({ verifier, cacheTtlMs: 1_000 });

    await pool.connect();
    expect(verifier.verify).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(1_001); // expire the cache entry

    await pool.connect();
    expect(verifier.verify).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  it("throws and releases client when quote is missing and allowSimulator is false", async () => {
    vi.mocked(extractTdxQuote).mockReturnValue(null);
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool({ allowSimulator: false });

    await expect(pool.connect()).rejects.toThrow("TDX attestation quote");
    expect((client.release as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith(true);
  });

  it("passes through when quote is missing and allowSimulator is true", async () => {
    vi.mocked(extractTdxQuote).mockReturnValue(null);
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool({ allowSimulator: true });

    await expect(pool.connect()).resolves.toBe(client);
  });

  it("throws and releases client when verifier.verify rejects", async () => {
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const verifier = {
      verify: vi.fn().mockRejectedValue(new Error("TCB OutOfDate")),
    };
    const pool = makePool({ verifier });

    await expect(pool.connect()).rejects.toThrow("TCB OutOfDate");
    expect((client.release as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith(true);
  });

  it("passes allowedMrTd and allowDebugMode through to the verifier", async () => {
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const verifier = { verify: vi.fn().mockResolvedValue({ tcbStatus: "UpToDate", isDebugMode: false, mrTd: "", rtmr0: "", rtmr1: "", rtmr2: "", rtmr3: "" }) };
    const pool = makePool({
      verifier,
      allowedMrTd: ["abc123"],
      allowDebugMode: true,
    });

    await pool.connect();
    expect(verifier.verify).toHaveBeenCalledWith(FAKE_QUOTE, {
      allowedMrTd: ["abc123"],
      allowDebugMode: true,
    });
  });

  it("evicts expired cache entries when cache exceeds 1000 entries", async () => {
    const client = makeClient(makeTlsSocket());
    mockSuperConnect.mockResolvedValue(client);
    const pool = makePool();

    // Pre-fill the internal cache with 1000 already-expired entries
    const internalCache = (pool as unknown as Record<string, Map<string, number>>)[
      "verifiedCerts"
    ]!;
    const past = Date.now() - 1;
    for (let i = 0; i < 1000; i++) {
      internalCache.set(`stale-hash-${i}`, past);
    }
    expect(internalCache.size).toBe(1000);

    // This connect adds entry 1001, triggering eviction of the 1000 stale entries
    await pool.connect();

    // All stale entries should have been evicted, leaving only the new one
    expect(internalCache.size).toBe(1);
  });
});
