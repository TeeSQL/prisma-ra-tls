import pg from "pg";
import tls from "tls";
import { createHash } from "crypto";
import { extractTdxQuote } from "./cert.js";
import type { RaTlsOptions } from "./types.js";

const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1_000; // 1 hour
const MAX_CACHE_ENTRIES = 1_000;

/**
 * A pg.Pool subclass that verifies TDX attestation on every new underlying
 * TCP connection to the database.
 *
 * Successful verifications are cached by certificate SHA-256 fingerprint.
 * The cache TTL defaults to 1 hour, matching Intel Trust Authority token
 * validity windows.
 */
export class RaTlsPool extends pg.Pool {
  // cert fingerprint (hex) → cache expiry (epoch ms)
  private readonly verifiedCerts = new Map<string, number>();

  constructor(
    config: pg.PoolConfig,
    private readonly raTlsOptions: RaTlsOptions
  ) {
    super(config);
  }

  override async connect(): Promise<pg.PoolClient> {
    const client = await super.connect();
    try {
      await this.verifyClientCert(client);
    } catch (err) {
      // Release back to pool before re-throwing so the pool stays healthy.
      // The underlying socket will be cleaned up by pg when it sees the
      // connection is broken.
      client.release(true /* destroyConnection */);
      throw err;
    }
    return client;
  }

  private async verifyClientCert(client: pg.PoolClient): Promise<void> {
    // Access pg's internal TLS socket. This uses pg internals that have been
    // stable across pg@7 and pg@8; we pin to pg>=8 in peerDependencies.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stream = (client as any).connection?.stream;
    if (!(stream instanceof tls.TLSSocket)) return;

    const peerCert = stream.getPeerCertificate(true);
    if (!peerCert?.raw) return;

    const certDer = Buffer.from(peerCert.raw);
    const fingerprint = createHash("sha256").update(certDer).digest("hex");

    // Cache hit — skip re-verification
    const expiry = this.verifiedCerts.get(fingerprint);
    if (expiry !== undefined && Date.now() < expiry) return;

    // Extract TDX quote from the RA-TLS certificate
    const quote = extractTdxQuote(certDer);

    if (quote === null) {
      if (this.raTlsOptions.allowSimulator) return; // non-TEE server, allowed in sim mode
      throw new Error(
        "Server TLS certificate does not contain a TDX attestation quote. " +
          "The server may not be running inside a dstack CVM. " +
          "Set allowSimulator: true if connecting to a simulator or non-TEE server."
      );
    }

    // Verify the quote via the configured verifier
    await this.raTlsOptions.verifier.verify(quote, {
      allowedMrTd: this.raTlsOptions.allowedMrTd,
      allowDebugMode: this.raTlsOptions.allowDebugMode,
    });

    // Cache the successful result
    const ttl = this.raTlsOptions.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.verifiedCerts.set(fingerprint, Date.now() + ttl);

    // Evict expired entries when cache grows large
    if (this.verifiedCerts.size > MAX_CACHE_ENTRIES) {
      this.evictExpired();
    }
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [fp, exp] of this.verifiedCerts) {
      if (now >= exp) this.verifiedCerts.delete(fp);
    }
  }
}
