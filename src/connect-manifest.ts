/**
 * Leader-discovery entrypoint: DNS TXT manifest → DSN rewrite → RA-TLS
 * connect. Wraps :func:`withRaTls` so the caller supplies a cluster domain
 * plus the manifest-signer address baked into the app, and we handle the
 * `_teesql-leader.<domain>` TXT lookup + signature verification.
 *
 * Failure modes (see spec §7.3):
 *   - TXT fetch / parse / signer mismatch → surfaces as a thrown Error.
 *   - Connection to manifest.leader_url fails → caller can refresh+retry.
 *   - Quote verification fails → hard failure (inside withRaTls).
 */

import type { PrismaPg } from "@prisma/adapter-pg";

import { withRaTls } from "./adapter.js";
import {
  buildRecordName,
  postgresHostFromLeaderUrl,
  queryManifestTxt,
} from "./discovery.js";
import { type Manifest, parseAndVerify } from "./manifest.js";
import type { RaTlsOptions } from "./types.js";

export async function resolveLeader(
  clusterDomain: string,
  manifestSigner: Uint8Array
): Promise<Manifest> {
  const record = buildRecordName(clusterDomain);
  const txt = await queryManifestTxt(record);
  return parseAndVerify(txt, manifestSigner);
}

function rewriteDsn(dsn: string, host: string, port: number): string {
  if (!(dsn.startsWith("postgresql://") || dsn.startsWith("postgres://"))) {
    throw new Error(
      "withRaTlsManifest requires a URI-form DSN (postgresql://user:pw@.../db)"
    );
  }
  const parsed = new URL(dsn);
  parsed.hostname = host;
  parsed.port = String(port);
  return parsed.toString();
}

/**
 * Discover the current leader via DNS TXT and open a verified RA-TLS
 * connection to it.
 *
 * @param clusterDomain   operator-owned domain (e.g. ``monitor.teesql.com``);
 *                        we look up ``_teesql-leader.<domain>``
 * @param dsnTemplate     URI-form DSN whose host:port will be overwritten
 *                        with the manifest's ``leader_url``; user, password,
 *                        database and query params are preserved
 * @param manifestSigner  20-byte ethereum-style address of the manifest
 *                        signer, baked into the SDK at build time
 * @param options         passed through to :func:`withRaTls`
 *
 * @example
 * ```ts
 * import { hexToBytes } from "@noble/hashes/utils";
 * const adapter = await withRaTlsManifest(
 *   "monitor.teesql.com",
 *   process.env.DATABASE_URL!,
 *   hexToBytes(process.env.TEESQL_MANIFEST_SIGNER!.slice(2)),
 *   { verifier: new IntelApiVerifier(), allowedMrTd: [MRTD] },
 * );
 * ```
 */
export async function withRaTlsManifest(
  clusterDomain: string,
  dsnTemplate: string,
  manifestSigner: Uint8Array,
  options: RaTlsOptions
): Promise<PrismaPg> {
  const manifest = await resolveLeader(clusterDomain, manifestSigner);
  const { host, port } = postgresHostFromLeaderUrl(manifest.leaderUrl);
  const dsn = rewriteDsn(dsnTemplate, host, port);
  return withRaTls(dsn, options);
}
