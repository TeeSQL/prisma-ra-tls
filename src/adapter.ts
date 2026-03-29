import { PrismaPg } from "@prisma/adapter-pg";
import { RaTlsPool } from "./pool.js";
import { getDstackClientCert } from "./dstack.js";
import type { RaTlsOptions } from "./types.js";

/**
 * Create a Prisma driver adapter that verifies TDX attestation before
 * allowing any queries through to a dstack RA-TLS secured Postgres instance.
 *
 * @example Server-only attestation (client can run anywhere):
 * ```ts
 * import { PrismaClient } from "@prisma/client"
 * import { withRaTls, IntelApiVerifier } from "prisma-ra-tls"
 *
 * const adapter = await withRaTls(process.env.DATABASE_URL!, {
 *   verifier: new IntelApiVerifier(),
 *   allowedMrTd: [process.env.EXPECTED_MRTD],
 * })
 * const prisma = new PrismaClient({ adapter })
 * ```
 *
 * @example Mutual RA-TLS (client must also be inside a dstack CVM):
 * ```ts
 * const adapter = await withRaTls(process.env.DATABASE_URL!, {
 *   verifier: new IntelApiVerifier(),
 *   clientAttestation: true,
 * })
 * ```
 *
 * @example Simulator / local dev (no attestation):
 * ```ts
 * const adapter = await withRaTls(process.env.DATABASE_URL!, {
 *   verifier: new NoopVerifier(),
 *   allowSimulator: true,
 * })
 * ```
 */
export async function withRaTls(
  connectionString: string,
  options: RaTlsOptions
): Promise<PrismaPg> {
  // Build the pg ssl options.
  // rejectUnauthorized must be false because RA-TLS certs are self-signed —
  // attestation verification is done by us, not the system CA store.
  let sslOptions: Record<string, unknown> = { rejectUnauthorized: false };

  if (options.clientAttestation) {
    const { key, cert } = await getDstackClientCert(options.dstackSocket);
    sslOptions = { ...sslOptions, key, cert };
  }

  const pool = new RaTlsPool(
    { connectionString, ssl: sslOptions },
    options
  );

  return new PrismaPg(pool, { schema: options.schema });
}
