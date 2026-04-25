import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/discovery.js", async () => {
  return {
    buildRecordName: vi.fn((d: string) =>
      d.startsWith("_teesql-leader.") ? d : `_teesql-leader.${d}`
    ),
    queryManifestTxt: vi.fn(async () => "mocked-txt-body"),
    postgresHostFromLeaderUrl: vi.fn(() => ({
      host: "leader.example",
      port: 443,
    })),
  };
});

vi.mock("../src/manifest.js", async () => {
  return {
    parseAndVerify: vi.fn(() => ({
      cluster: "0xfeedface",
      leaderInstance: "0".repeat(64),
      leaderUrl: "https://leader.example/",
      epoch: 1,
      validUntil: 9_999_999_999,
    })),
    canonicalBody: vi.fn(),
    MANIFEST_VERSION: "1",
    ManifestError: class ManifestError extends Error {},
  };
});

const startSpy = vi.fn(async () => ({ host: "127.0.0.1", port: 11111 }));

vi.mock("../src/forwarder.js", () => {
  return {
    RaTlsForwarder: class {
      public localAddr = { host: "127.0.0.1", port: 11111 };
      async start() {
        return startSpy();
      }
      async stop() {
        /* */
      }
    },
    registerForwarder: vi.fn(),
    registeredForwarders: vi.fn(() => []),
  };
});

vi.mock("../src/dstack.js", () => ({
  getDstackClientCert: vi.fn().mockResolvedValue({
    key: Buffer.from("k"),
    cert: Buffer.from("c"),
    certChainPem: "c\n",
  }),
}));

vi.mock("@prisma/adapter-pg", () => ({
  PrismaPg: vi.fn().mockImplementation((cfg, opts) => ({
    cfg,
    opts,
    _type: "PrismaPg",
  })),
}));

import {
  connectViaManifest,
  resolveLeader,
  withRaTlsManifest,
} from "../src/connect-manifest.js";
import { NoopVerifier } from "../src/verifiers/noop.js";
import { PrismaPg } from "@prisma/adapter-pg";
import { queryManifestTxt, buildRecordName } from "../src/discovery.js";
import { parseAndVerify } from "../src/manifest.js";

const SIGNER = new Uint8Array(20);
const TEMPLATE_DSN = "postgresql://teesql_readwrite:s@placeholder:5433/db";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("resolveLeader", () => {
  it("queries `_teesql-leader.<domain>` and verifies the manifest", async () => {
    const m = await resolveLeader("monitor.teesql.com", SIGNER);
    expect(buildRecordName).toHaveBeenCalledWith("monitor.teesql.com");
    expect(queryManifestTxt).toHaveBeenCalled();
    expect(parseAndVerify).toHaveBeenCalled();
    expect(m.cluster).toBe("0xfeedface");
  });
});

describe("connectViaManifest", () => {
  it("returns a localhost DSN with sslmode=disable", async () => {
    const { dsn } = await connectViaManifest(
      "monitor.teesql.com",
      TEMPLATE_DSN,
      SIGNER,
      { verifier: new NoopVerifier() }
    );
    const parsed = new URL(dsn);
    expect(parsed.hostname).toBe("127.0.0.1");
    expect(parsed.port).toBe("11111");
    expect(parsed.searchParams.get("sslmode")).toBe("disable");
    expect(parsed.username).toBe("teesql_readwrite");
  });

  it("returns the verified manifest", async () => {
    const { manifest } = await connectViaManifest(
      "monitor.teesql.com",
      TEMPLATE_DSN,
      SIGNER,
      { verifier: new NoopVerifier() }
    );
    expect(manifest.epoch).toBe(1);
    expect(manifest.leaderUrl).toBe("https://leader.example/");
  });

  it("returns a started forwarder", async () => {
    const { forwarder } = await connectViaManifest(
      "monitor.teesql.com",
      TEMPLATE_DSN,
      SIGNER,
      { verifier: new NoopVerifier() }
    );
    expect(startSpy).toHaveBeenCalled();
    expect(forwarder.localAddr.port).toBe(11111);
  });
});

describe("withRaTlsManifest (legacy compat wrapper)", () => {
  it("returns a PrismaPg adapter built from the local DSN", async () => {
    const adapter = await withRaTlsManifest(
      "monitor.teesql.com",
      TEMPLATE_DSN,
      SIGNER,
      { verifier: new NoopVerifier() }
    );
    expect(adapter).toMatchObject({ _type: "PrismaPg" });
    const callArgs = vi.mocked(PrismaPg).mock.calls[0];
    expect(callArgs?.[0]).toMatchObject({
      connectionString: expect.stringContaining("127.0.0.1"),
    });
  });

  it("forwards schema option through to PrismaPg", async () => {
    await withRaTlsManifest("monitor.teesql.com", TEMPLATE_DSN, SIGNER, {
      verifier: new NoopVerifier(),
      schema: "myschema",
    });
    const opts = vi.mocked(PrismaPg).mock.calls[0]?.[1];
    expect(opts).toEqual({ schema: "myschema" });
  });
});
