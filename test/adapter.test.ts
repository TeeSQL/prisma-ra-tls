import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks — must be declared before imports
// ---------------------------------------------------------------------------

vi.mock("../src/pool.js", () => ({
  RaTlsPool: vi.fn().mockImplementation((config, opts) => ({ config, opts })),
}));

vi.mock("../src/dstack.js", () => ({
  getDstackClientCert: vi.fn().mockResolvedValue({
    key: Buffer.from("client-key"),
    cert: Buffer.from("client-cert"),
    certChainPem: "client-cert\n",
  }),
}));

vi.mock("@prisma/adapter-pg", () => ({
  PrismaPg: vi.fn().mockImplementation((pool, opts) => ({ pool, opts, _type: "PrismaPg" })),
}));

import { withRaTls } from "../src/adapter.js";
import { RaTlsPool } from "../src/pool.js";
import { getDstackClientCert } from "../src/dstack.js";
import { PrismaPg } from "@prisma/adapter-pg";
import { NoopVerifier } from "../src/verifiers/noop.js";

const CONNECTION_STRING = "postgresql://postgres@localhost:5433/db";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("withRaTls", () => {
  it("returns a PrismaPg adapter", async () => {
    const adapter = await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
    });
    expect(adapter).toMatchObject({ _type: "PrismaPg" });
  });

  it("creates a RaTlsPool with the connection string", async () => {
    await withRaTls(CONNECTION_STRING, { verifier: new NoopVerifier() });
    expect(RaTlsPool).toHaveBeenCalledWith(
      expect.objectContaining({ connectionString: CONNECTION_STRING }),
      expect.anything()
    );
  });

  it("sets ssl.rejectUnauthorized=false on the pool config", async () => {
    await withRaTls(CONNECTION_STRING, { verifier: new NoopVerifier() });
    const poolConfig = vi.mocked(RaTlsPool).mock.calls[0]?.[0];
    expect((poolConfig?.ssl as Record<string, unknown>)?.rejectUnauthorized).toBe(false);
  });

  it("does NOT call getDstackClientCert when clientAttestation is false (default)", async () => {
    await withRaTls(CONNECTION_STRING, { verifier: new NoopVerifier() });
    expect(getDstackClientCert).not.toHaveBeenCalled();
  });

  it("calls getDstackClientCert when clientAttestation is true", async () => {
    await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
      clientAttestation: true,
    });
    expect(getDstackClientCert).toHaveBeenCalledTimes(1);
  });

  it("uses default socket path when clientAttestation is true and dstackSocket is not set", async () => {
    await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
      clientAttestation: true,
    });
    expect(getDstackClientCert).toHaveBeenCalledWith(undefined);
  });

  it("passes dstackSocket option to getDstackClientCert", async () => {
    await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
      clientAttestation: true,
      dstackSocket: "/custom/dstack.sock",
    });
    expect(getDstackClientCert).toHaveBeenCalledWith("/custom/dstack.sock");
  });

  it("includes client key+cert in ssl options when clientAttestation is true", async () => {
    await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
      clientAttestation: true,
    });
    const poolConfig = vi.mocked(RaTlsPool).mock.calls[0]?.[0];
    const ssl = poolConfig?.ssl as Record<string, unknown>;
    expect(ssl?.key).toEqual(Buffer.from("client-key"));
    expect(ssl?.cert).toEqual(Buffer.from("client-cert"));
  });

  it("passes schema option through to PrismaPg", async () => {
    await withRaTls(CONNECTION_STRING, {
      verifier: new NoopVerifier(),
      schema: "myschema",
    });
    expect(PrismaPg).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ schema: "myschema" })
    );
  });

  it("passes undefined schema to PrismaPg when not set", async () => {
    await withRaTls(CONNECTION_STRING, { verifier: new NoopVerifier() });
    expect(PrismaPg).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ schema: undefined })
    );
  });

  it("passes full RaTlsOptions to RaTlsPool", async () => {
    const verifier = new NoopVerifier();
    await withRaTls(CONNECTION_STRING, {
      verifier,
      allowedMrTd: ["abc"],
      allowDebugMode: true,
      allowSimulator: true,
      cacheTtlMs: 500,
    });
    expect(RaTlsPool).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        verifier,
        allowedMrTd: ["abc"],
        allowDebugMode: true,
        allowSimulator: true,
        cacheTtlMs: 500,
      })
    );
  });
});
