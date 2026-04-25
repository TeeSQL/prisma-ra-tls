/**
 * Leader-discovery entrypoint for prisma-ra-tls v0.3.0: DNS TXT manifest
 * → localhost RA-TLS forwarder → DSN rewrite. Returns a local DSN the
 * caller passes to ``PrismaPg`` (or any node-postgres ``Pool``) directly.
 *
 * Why the API moved
 * -----------------
 *
 * v0.2.x exposed ``withRaTlsManifest`` which built a ``PrismaPg`` adapter
 * directly using ``pg``'s in-driver TLS. That model breaks the dstack
 * gateway's TLS-passthrough SNI router because node-postgres opens every
 * SSL connection with the postgres ``SSLRequest`` 8-byte plaintext
 * preamble — the gateway sees ``0x00`` (not ``0x16``) and tears the
 * connection down before the ClientHello arrives. See
 * :file:`forwarder.ts` for the full rationale.
 *
 * v0.3.0 inverts the flow:
 *
 *   1. Resolve the leader via ``_teesql-leader.<domain>`` TXT.
 *   2. Verify the manifest signature.
 *   3. Spawn an in-process RA-TLS forwarder on
 *      ``127.0.0.1:<ephemeral>``.
 *   4. Return a localhost DSN with ``sslmode=disable``.
 *
 * The caller passes that DSN to ``PrismaPg`` (or whatever node-postgres
 * client) just like a vanilla local postgres URL.
 *
 * Failure modes (see spec §7.3):
 *   - TXT fetch / parse / signer mismatch → surfaces as a thrown ``Error``.
 *   - Forwarder bind fails → throws synchronously from ``connectViaManifest``.
 *   - First connection's RA-TLS handshake fails → surfaces as a postgres
 *     connection error from node-postgres.
 *
 * Migration from v0.2.x
 * ---------------------
 *
 * v0.2.x callers using ``withRaTlsManifest`` should migrate:
 *
 * .. code-block:: ts
 *
 *   // Old (v0.2.x):
 *   const adapter = await withRaTlsManifest(domain, dsn, signer, opts);
 *   const prisma = new PrismaClient({ adapter });
 *
 *   // New (v0.3.0):
 *   const { dsn: localDsn } = await connectViaManifest(domain, dsn, signer, opts);
 *   const adapter = new PrismaPg({ connectionString: localDsn });
 *   const prisma = new PrismaClient({ adapter });
 *
 * The legacy ``withRaTlsManifest`` symbol remains as a thin wrapper
 * that does the same forwarder dance and then constructs the adapter,
 * so existing callers keep working but lose direct access to the local
 * DSN.
 */
import { PrismaPg } from "@prisma/adapter-pg";

import {
  buildRecordName,
  postgresHostFromLeaderUrl,
  queryManifestTxt,
} from "./discovery.js";
import { type Manifest, parseAndVerify } from "./manifest.js";
import {
  openLocalForwarder,
  rewriteDsnToForwarder,
  type OpenForwarderOptions,
} from "./connect.js";
import { RaTlsForwarder } from "./forwarder.js";

export async function resolveLeader(
  clusterDomain: string,
  manifestSigner: Uint8Array
): Promise<Manifest> {
  const record = buildRecordName(clusterDomain);
  const txt = await queryManifestTxt(record);
  return parseAndVerify(txt, manifestSigner);
}

/** Result of {@link connectViaManifest}. */
export interface ManifestConnection {
  /**
   * Loopback DSN pointing at the in-process RA-TLS forwarder. Pass this
   * to ``new PrismaPg({ connectionString: dsn })`` or any other
   * node-postgres-compatible client. The DSN has ``sslmode=disable``;
   * the forwarder owns the TLS layer.
   */
  dsn: string;
  /**
   * The verified DNS-TXT manifest. Useful for telemetry / debugging
   * (cluster id, epoch, leader URL).
   */
  manifest: Manifest;
  /** Handle to the running forwarder. Most callers can ignore this. */
  forwarder: RaTlsForwarder;
}

/** Options for {@link connectViaManifest}. */
export interface ConnectViaManifestOptions extends OpenForwarderOptions {
  /**
   * Schema override forwarded into the legacy ``withRaTlsManifest``
   * wrapper. Ignored by the v0.3.0 forwarder-only path. Kept here for
   * source-level compatibility with v0.2.x callers.
   */
  schema?: string;
}

/**
 * Discover the current leader via DNS TXT, start an in-process
 * mutual-RA-TLS forwarder pointing at it, and return a localhost DSN
 * the caller can feed directly to PrismaPg.
 *
 * The forwarder is module-registered so it survives for the lifetime
 * of the process, matching the typical "one-pool-per-service" usage.
 *
 * @example
 * ```ts
 * import { hexToBytes } from "@noble/hashes/utils";
 * import { PrismaPg } from "@prisma/adapter-pg";
 * import { PrismaClient } from "@prisma/client";
 * import { connectViaManifest, NoopVerifier } from "prisma-ra-tls";
 *
 * const { dsn } = await connectViaManifest(
 *   "62e509856e.teesql.com",
 *   process.env.DATABASE_URL!,
 *   hexToBytes(process.env.TEESQL_MANIFEST_SIGNER!.slice(2)),
 *   { verifier: new NoopVerifier(), allowSimulator: false },
 * );
 *
 * const adapter = new PrismaPg({ connectionString: dsn });
 * const prisma = new PrismaClient({ adapter });
 * ```
 */
export async function connectViaManifest(
  clusterDomain: string,
  dsnTemplate: string,
  manifestSigner: Uint8Array,
  options: ConnectViaManifestOptions
): Promise<ManifestConnection> {
  const manifest = await resolveLeader(clusterDomain, manifestSigner);
  const { host, port } = postgresHostFromLeaderUrl(manifest.leaderUrl);
  const forwarder = await openLocalForwarder(host, port, options);
  const localAddr = forwarder.localAddr;
  const dsn = rewriteDsnToForwarder(
    dsnTemplate,
    localAddr.host,
    localAddr.port
  );
  return { dsn, manifest, forwarder };
}

/**
 * v0.2.x-compatible wrapper that returns a ``PrismaPg`` adapter rather
 * than a localhost DSN. Internally it now uses the same forwarder
 * machinery as {@link connectViaManifest}; the only difference is
 * convenience.
 *
 * Prefer {@link connectViaManifest} for new code — it gives you the
 * verified manifest and a forwarder handle for explicit lifecycle
 * control.
 *
 * @deprecated since 0.3.0 — use {@link connectViaManifest} instead.
 */
export async function withRaTlsManifest(
  clusterDomain: string,
  dsnTemplate: string,
  manifestSigner: Uint8Array,
  options: ConnectViaManifestOptions
): Promise<PrismaPg> {
  const { dsn } = await connectViaManifest(
    clusterDomain,
    dsnTemplate,
    manifestSigner,
    options
  );
  // Use PrismaPg's connection-string constructor, then forward the
  // schema override the same way v0.2.x did.
  return new PrismaPg({ connectionString: dsn }, { schema: options.schema });
}
