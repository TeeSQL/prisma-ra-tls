/**
 * DNS TXT discovery helpers for the leader manifest flow.
 *
 * The manifest lives at ``_teesql-leader.<cluster_domain>`` and is signed by
 * the KMS-derived manifest-signer key. See
 * docs/specs/cluster-endpoint-registry.md §7 for the on-chain → DNS flow.
 */

import { promises as dns } from "node:dns";

export const LEADER_RECORD_LABEL = "_teesql-leader";

/**
 * ``monitor.teesql.com`` → ``_teesql-leader.monitor.teesql.com``. Idempotent
 * — if the caller already passed the fully-qualified label, return it as-is.
 */
export function buildRecordName(clusterDomain: string): string {
  if (clusterDomain.startsWith(`${LEADER_RECORD_LABEL}.`)) return clusterDomain;
  return `${LEADER_RECORD_LABEL}.${clusterDomain}`;
}

/**
 * Resolve the TXT at ``recordName`` and return the first record whose
 * content looks like a signed manifest (contains ``;sig=``). Multi-chunk
 * TXT records (each chunk ≤255 bytes) are joined.
 */
export async function queryManifestTxt(recordName: string): Promise<string> {
  const records = await dns.resolveTxt(recordName);
  if (records.length === 0) {
    throw new Error(`no TXT records for ${recordName}`);
  }
  for (const record of records) {
    const joined = record.join("");
    if (joined.includes(";sig=")) return joined;
  }
  throw new Error(`no TXT record with sig field for ${recordName}`);
}

/**
 * Derive (host, port) for the postgres socket from the manifest's
 * ``leader_url``. Dstack gateway publishes https:// URLs; port falls back
 * to the scheme default when absent.
 */
export function postgresHostFromLeaderUrl(url: string): { host: string; port: number } {
  const parsed = new URL(url);
  if (!parsed.hostname) throw new Error(`missing hostname: ${url}`);
  if (parsed.port) return { host: parsed.hostname, port: Number(parsed.port) };
  if (parsed.protocol === "https:") return { host: parsed.hostname, port: 443 };
  if (parsed.protocol === "http:") return { host: parsed.hostname, port: 80 };
  throw new Error(`unknown scheme for ${url}: ${parsed.protocol}`);
}
