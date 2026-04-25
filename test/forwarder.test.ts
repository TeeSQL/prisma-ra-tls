import { describe, it, expect, beforeEach, vi } from "vitest";
import { createServer as createTlsServer, type TLSSocket } from "node:tls";
import { connect as netConnect } from "node:net";
import {
  X509CertificateGenerator,
  Extension,
} from "@peculiar/x509";

import {
  RaTlsForwarder,
  registerForwarder,
  registeredForwarders,
} from "../src/forwarder.js";
import { NoopVerifier } from "../src/verifiers/noop.js";
import type { RaTlsVerifier, VerificationResult } from "../src/types.js";
import { makeDerOctetString } from "./helpers.js";

const OID_TDX_QUOTE = "1.3.6.1.4.1.62397.1.1";

// ---------------------------------------------------------------------------
// Build a self-signed RSA cert + key with an optional fake TDX-quote
// extension. We generate via Node's WebCrypto subtle so peculiar/x509 can
// sign with the resulting CryptoKeyPair, then export the private key as
// PKCS#8 PEM so node-tls can load it.
// ---------------------------------------------------------------------------

interface KeyPair {
  keyPem: string;
  certPem: string;
  certDer: Buffer;
}

async function buildSelfSignedCert(withTdxExtension: boolean): Promise<KeyPair> {
  const subtleKeys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const extensions: Extension[] = [];
  if (withTdxExtension) {
    extensions.push(
      new Extension(
        OID_TDX_QUOTE,
        false,
        makeDerOctetString(Buffer.from("fake-tdx-quote-bytes"))
      )
    );
  }

  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=test-server",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 60 * 60 * 1000),
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys: subtleKeys,
    extensions,
  });

  // Export the subtle private key as PEM PKCS#8 so node-tls can load it.
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", subtleKeys.privateKey);
  const subtleKeyPem = derToPem(Buffer.from(pkcs8), "PRIVATE KEY");

  return {
    keyPem: subtleKeyPem,
    certPem: cert.toString("pem"),
    certDer: Buffer.from(cert.rawData),
  };
}

function derToPem(der: Buffer, label: string): string {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

// ---------------------------------------------------------------------------
// Spin up a local TLS server that immediately echoes whatever it receives.
// ---------------------------------------------------------------------------

interface TestUpstream {
  port: number;
  close: () => Promise<void>;
  receivedBytes: Buffer[];
  awaitClient: () => Promise<TLSSocket>;
}

async function startTlsEchoServer(cert: KeyPair): Promise<TestUpstream> {
  const received: Buffer[] = [];
  let resolveClient: (s: TLSSocket) => void;
  const clientPromise = new Promise<TLSSocket>((r) => (resolveClient = r));

  const server = createTlsServer(
    {
      key: cert.keyPem,
      cert: cert.certPem,
      requestCert: false,
    },
    (sock) => {
      resolveClient(sock);
      sock.on("data", (chunk) => {
        received.push(chunk);
        sock.write(chunk); // echo
      });
      sock.on("error", () => {
        /* ignore */
      });
    }
  );
  server.on("tlsClientError", () => {
    /* ignore mid-handshake closes from tests */
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (typeof addr !== "object" || addr === null) {
    throw new Error("server did not bind");
  }
  return {
    port: addr.port,
    receivedBytes: received,
    awaitClient: () => clientPromise,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RaTlsForwarder", () => {
  let serverCert: KeyPair;
  let upstream: TestUpstream;

  beforeEach(async () => {
    serverCert = await buildSelfSignedCert(true);
    upstream = await startTlsEchoServer(serverCert);
  });

  it("binds to 127.0.0.1 on a random port", async () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    const addr = await fwd.start();
    try {
      expect(addr.host).toBe("127.0.0.1");
      expect(addr.port).toBeGreaterThan(0);
      expect(fwd.localAddr.port).toBe(addr.port);
    } finally {
      await fwd.stop();
    }
    await upstream.close();
  });

  it("throws when localAddr accessed before start()", () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    expect(() => fwd.localAddr).toThrow("start() has not been called");
    upstream.close();
  });

  it("bridges bytes via mutual-RA-TLS terminated upstream", async () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    const { port } = await fwd.start();

    // Connect a plain-TCP client to the forwarder, send some bytes,
    // expect them echoed back.
    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
      local.once("connect", () => resolve());
      local.once("error", reject);
    });

    const payload = Buffer.from("hello forwarder");
    local.write(payload);

    const received = await new Promise<Buffer>((resolve) => {
      local.once("data", (chunk) => resolve(chunk));
    });
    expect(received.toString()).toBe("hello forwarder");

    await new Promise<void>((resolve) => {
      local.end(() => resolve());
    });
    await fwd.stop();
    await upstream.close();
  });

  it("calls the verifier with the extracted upstream quote", async () => {
    const verifier = {
      verify: vi.fn(async (): Promise<VerificationResult> => ({
        mrTd: "0".repeat(96),
        rtmr0: "0".repeat(96),
        rtmr1: "0".repeat(96),
        rtmr2: "0".repeat(96),
        rtmr3: "0".repeat(96),
        tcbStatus: "UpToDate",
        isDebugMode: false,
      })),
    } satisfies RaTlsVerifier;
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier,
      verifyOptions: { allowDebugMode: false },
    });
    const { port } = await fwd.start();

    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
      local.once("connect", () => resolve());
      local.once("error", reject);
    });
    local.write(Buffer.from("hi"));
    await new Promise<Buffer>((resolve) => local.once("data", resolve));

    expect(verifier.verify).toHaveBeenCalledTimes(1);
    const [quote, opts] = verifier.verify.mock.calls[0] ?? [];
    expect(Buffer.isBuffer(quote)).toBe(true);
    expect((quote as Buffer).toString()).toBe("fake-tdx-quote-bytes");
    expect(opts).toEqual({ allowDebugMode: false });

    local.destroy();
    await fwd.stop();
    await upstream.close();
  });

  it("rejects when upstream cert has no TDX extension and !allowSimulator", async () => {
    const plainCert = await buildSelfSignedCert(false);
    const upstreamPlain = await startTlsEchoServer(plainCert);

    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstreamPlain.port,
      clientCertChainPem: plainCert.certPem,
      clientKeyPem: plainCert.keyPem,
      verifier: new NoopVerifier(),
      allowSimulator: false,
    });
    const { port } = await fwd.start();

    // Local side: pg/node-postgres would just see the TCP connection
    // dropping. Watch for `close` to confirm the forwarder tore it down.
    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve) => {
      local.once("close", () => resolve());
      local.once("connect", () => {
        // local accepted, but forwarder will drop after upstream check fails
      });
    });

    await fwd.stop();
    await upstreamPlain.close();
  });

  it("permits upstream with no TDX extension when allowSimulator=true", async () => {
    const plainCert = await buildSelfSignedCert(false);
    const upstreamPlain = await startTlsEchoServer(plainCert);

    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstreamPlain.port,
      clientCertChainPem: plainCert.certPem,
      clientKeyPem: plainCert.keyPem,
      verifier: new NoopVerifier(),
      allowSimulator: true,
    });
    const { port } = await fwd.start();

    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
      local.once("connect", () => resolve());
      local.once("error", reject);
    });
    local.write(Buffer.from("simulator-hello"));
    const echoed = await new Promise<Buffer>((resolve) =>
      local.once("data", resolve)
    );
    expect(echoed.toString()).toBe("simulator-hello");

    local.destroy();
    await fwd.stop();
    await upstreamPlain.close();
  });

  it("stop() is idempotent", async () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    await fwd.start();
    await fwd.stop();
    await fwd.stop();
    await upstream.close();
  });

  it("cleans up a bridge when local closes", async () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    const { port } = await fwd.start();
    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve) => local.once("connect", resolve));
    local.write(Buffer.from("x"));
    await new Promise<Buffer>((resolve) => local.once("data", resolve));
    local.destroy();
    // Give a tick for cleanup to drain.
    await new Promise((r) => setTimeout(r, 10));
    await fwd.stop();
    await upstream.close();
  });

  it("rejects upstream connection on connect error", async () => {
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      // Use a port that is almost certainly closed
      targetPort: 1,
      clientCertChainPem: serverCert.certPem,
      clientKeyPem: serverCert.keyPem,
      verifier: new NoopVerifier(),
    });
    const { port } = await fwd.start();

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve) => local.once("close", () => resolve()));
    warnSpy.mockRestore();
    await fwd.stop();
    await upstream.close();
  });
});

describe("forwarder registry", () => {
  it("registers and lists forwarders", async () => {
    const beforeCount = registeredForwarders().length;
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: 1,
      clientCertChainPem: "x",
      clientKeyPem: "y",
      verifier: new NoopVerifier(),
    });
    registerForwarder(fwd);
    expect(registeredForwarders().length).toBe(beforeCount + 1);
  });
});

// ---------------------------------------------------------------------------
// Coverage tail: error paths that don't happen on the happy bridge path.
// ---------------------------------------------------------------------------

describe("RaTlsForwarder error paths", () => {
  it("propagates a verifier rejection as a connection drop", async () => {
    const cert = await buildSelfSignedCert(true);
    const upstream = await startTlsEchoServer(cert);
    const verifier: RaTlsVerifier = {
      verify: vi.fn().mockRejectedValue(new Error("MRTD mismatch")),
    };
    const fwd = new RaTlsForwarder({
      targetHost: "127.0.0.1",
      targetPort: upstream.port,
      clientCertChainPem: cert.certPem,
      clientKeyPem: cert.keyPem,
      verifier,
    });
    const { port } = await fwd.start();

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const local = netConnect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve) => local.once("close", () => resolve()));
    warnSpy.mockRestore();
    expect(verifier.verify).toHaveBeenCalled();

    await fwd.stop();
    await upstream.close();
  });
});
