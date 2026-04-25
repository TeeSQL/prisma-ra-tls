import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/dstack.js", () => ({
  getDstackClientCert: vi.fn().mockResolvedValue({
    key: Buffer.from("fake-key-pem"),
    cert: Buffer.from("fake-leaf-pem"),
    certChainPem: "fake-leaf-pem\nfake-intermediate-pem\n",
  }),
}));

const startSpy = vi.fn(async () => ({ host: "127.0.0.1", port: 54321 }));
const stopSpy = vi.fn(async () => {});
let lastFwdInstance: { localAddr: { host: string; port: number } } | null =
  null;

vi.mock("../src/forwarder.js", () => {
  return {
    RaTlsForwarder: class {
      public localAddr = { host: "127.0.0.1", port: 54321 };
      constructor(_opts: unknown) {
        lastFwdInstance = this;
      }
      async start(): Promise<{ host: string; port: number }> {
        return startSpy();
      }
      async stop(): Promise<void> {
        return stopSpy();
      }
    },
    registerForwarder: vi.fn(),
    registeredForwarders: vi.fn(() => []),
  };
});

import {
  openLocalForwarder,
  rewriteDsnToForwarder,
  parseDsnTarget,
} from "../src/connect.js";
import { getDstackClientCert } from "../src/dstack.js";
import { registerForwarder } from "../src/forwarder.js";
import { NoopVerifier } from "../src/verifiers/noop.js";

beforeEach(() => {
  vi.clearAllMocks();
  lastFwdInstance = null;
});

describe("openLocalForwarder", () => {
  it("fetches a client cert with usage_ra_tls=true and usage_client_auth=true", async () => {
    await openLocalForwarder("upstream.example", 5433, {
      verifier: new NoopVerifier(),
    });
    expect(getDstackClientCert).toHaveBeenCalledWith(undefined, {
      usageRaTls: true,
      usageServerAuth: true,
      usageClientAuth: true,
    });
  });

  it("propagates dstackSocket override", async () => {
    await openLocalForwarder("upstream.example", 5433, {
      verifier: new NoopVerifier(),
      dstackSocket: "/tmp/dstack.sock",
    });
    expect(getDstackClientCert).toHaveBeenCalledWith(
      "/tmp/dstack.sock",
      expect.anything()
    );
  });

  it("starts the forwarder and registers it module-globally", async () => {
    await openLocalForwarder("upstream.example", 5433, {
      verifier: new NoopVerifier(),
    });
    expect(startSpy).toHaveBeenCalledTimes(1);
    expect(registerForwarder).toHaveBeenCalledTimes(1);
  });

  it("returns a forwarder whose localAddr is bound", async () => {
    const fwd = await openLocalForwarder("upstream.example", 5433, {
      verifier: new NoopVerifier(),
    });
    expect(fwd.localAddr).toEqual({ host: "127.0.0.1", port: 54321 });
  });
});

describe("rewriteDsnToForwarder", () => {
  it("rewrites the host and port to the forwarder address", () => {
    const dsn = "postgresql://teesql_readwrite:secret@upstream.example:5433/mydb";
    const out = rewriteDsnToForwarder(dsn, "127.0.0.1", 12345);
    const parsed = new URL(out);
    expect(parsed.hostname).toBe("127.0.0.1");
    expect(parsed.port).toBe("12345");
    expect(parsed.username).toBe("teesql_readwrite");
    expect(parsed.password).toBe("secret");
    expect(parsed.pathname).toBe("/mydb");
    expect(parsed.searchParams.get("sslmode")).toBe("disable");
  });

  it("forces sslmode=disable, replacing any existing sslmode", () => {
    const dsn =
      "postgresql://u:p@h:1/d?sslmode=require&application_name=foo";
    const out = rewriteDsnToForwarder(dsn, "127.0.0.1", 1);
    const parsed = new URL(out);
    expect(parsed.searchParams.get("sslmode")).toBe("disable");
    expect(parsed.searchParams.get("application_name")).toBe("foo");
  });

  it("substitutes a placeholder password when DSN has none", () => {
    const dsn = "postgresql://teesql_readwrite@h:1/d";
    const out = rewriteDsnToForwarder(dsn, "127.0.0.1", 1);
    const parsed = new URL(out);
    expect(parsed.username).toBe("teesql_readwrite");
    expect(parsed.password).toBe("ratls");
  });

  it("rejects non-URL-form DSNs", () => {
    expect(() =>
      rewriteDsnToForwarder("host=h port=1 user=u password=p dbname=d", "127.0.0.1", 1)
    ).toThrow("URI-form DSN");
  });
});

describe("parseDsnTarget", () => {
  it("returns host and explicit port", () => {
    const t = parseDsnTarget("postgres://u:p@example.com:5433/db");
    expect(t).toEqual({ host: "example.com", port: 5433 });
  });

  it("defaults port to 5432 when not present", () => {
    const t = parseDsnTarget("postgres://u:p@example.com/db");
    expect(t).toEqual({ host: "example.com", port: 5432 });
  });

  it("rejects keyword-form DSNs", () => {
    expect(() => parseDsnTarget("host=h port=1")).toThrow("URI-form DSN");
  });

  it("rejects DSN with no host", () => {
    // URL without authority component — `postgresql:///db` → hostname empty
    expect(() => parseDsnTarget("postgresql:///db")).toThrow("DSN has no host");
  });
});
