/**
 * Signed DNS TXT manifest verification for TeeSQL endpoint-registry v2.
 *
 * The canonical body format is also produced by the Rust controller crate
 * (crates/dns-controller/src/manifest.rs) and the Python SDK
 * (psycopg-ra-tls). All three implementations MUST agree byte-for-byte on
 * the pre-signing string — the `canonical_body_golden_string` test in each
 * language pins the exact bytes so a drift on any side surfaces as a failure
 * in at least two test suites.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

export const MANIFEST_VERSION = "1";

export interface Manifest {
  /** Cluster contract address, lowercase "0x"-prefixed. */
  cluster: string;
  /** 32-byte instance id as 64 hex chars (no 0x). */
  leaderInstance: string;
  /** Absolute URL of the leader's postgres endpoint. */
  leaderUrl: string;
  epoch: number;
  /** Unix seconds after which the manifest must be rejected. */
  validUntil: number;
}

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}

export function canonicalBody(m: Manifest): string {
  const parts: [string, string][] = [
    ["cluster", m.cluster.toLowerCase()],
    ["epoch", String(m.epoch)],
    ["leader_instance", m.leaderInstance.toLowerCase()],
    ["leader_url", m.leaderUrl],
    ["v", MANIFEST_VERSION],
    ["valid_until", String(m.validUntil)],
  ];
  return parts.map(([k, v]) => `${k}=${v}`).join(";");
}

function parseFields(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of body.split(";")) {
    const idx = pair.indexOf("=");
    if (idx < 0) throw new ManifestError(`malformed field: ${pair}`);
    const k = pair.slice(0, idx);
    const v = pair.slice(idx + 1);
    out[k] = v;
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new ManifestError("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new ManifestError(`invalid hex: ${hex}`);
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Parse a signed TXT body and verify the signature against ``expectedSigner``.
 *
 * Accepts the exact string the dns-controller writes:
 *   ``cluster=0x..;epoch=N;leader_instance=..;leader_url=..;v=1;valid_until=N;sig=0x<130hex>``
 *
 * @param txt           full TXT content
 * @param expectedSigner 20-byte ethereum-style address of the manifest-signer
 *                       key (derived from the KMS-derived app-scoped key)
 * @param opts.now       override current unix time for expiry testing
 */
export function parseAndVerify(
  txt: string,
  expectedSigner: Uint8Array,
  opts?: { now?: number }
): Manifest {
  if (expectedSigner.length !== 20) {
    throw new ManifestError("expectedSigner must be 20 bytes");
  }
  const sigIdx = txt.lastIndexOf(";sig=");
  if (sigIdx < 0) throw new ManifestError("missing sig field");
  const body = txt.slice(0, sigIdx);
  const sigStr = txt.slice(sigIdx + ";sig=".length);
  if (!sigStr.startsWith("0x")) throw new ManifestError("sig must be 0x-prefixed");
  const sigBytes = hexToBytes(sigStr.slice(2));
  if (sigBytes.length !== 65) throw new ManifestError("sig must be 65 bytes");

  const fields = parseFields(body);
  const version = fields["v"];
  if (version !== MANIFEST_VERSION) {
    throw new ManifestError(`unsupported manifest version: ${version}`);
  }
  for (const k of ["cluster", "epoch", "leader_instance", "leader_url", "valid_until"]) {
    if (!(k in fields)) throw new ManifestError(`missing field: ${k}`);
  }
  const validUntil = Number(fields["valid_until"]);
  if (!Number.isFinite(validUntil)) {
    throw new ManifestError(`invalid valid_until: ${fields["valid_until"]}`);
  }
  const now = opts?.now ?? Math.floor(Date.now() / 1000);
  if (validUntil <= now) {
    throw new ManifestError(`expired: valid_until=${validUntil} now=${now}`);
  }

  // EIP-191 prefix: "\x19Ethereum Signed Message:\n" || len(body) || body
  const encoder = new TextEncoder();
  const prefix = encoder.encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const bodyBytes = encoder.encode(body);
  const digest = keccak_256(concat(prefix, bodyBytes));

  const r = sigBytes.slice(0, 32);
  const s = sigBytes.slice(32, 64);
  const v = sigBytes[64];
  if (v === undefined) throw new ManifestError("sig missing recovery byte");
  const recid = v >= 27 ? v - 27 : v;
  if (recid !== 0 && recid !== 1) {
    throw new ManifestError(`invalid recovery id: ${v}`);
  }

  const sig = secp256k1.Signature.fromCompact(concat(r, s)).addRecoveryBit(recid);
  const pub = sig.recoverPublicKey(digest);
  // Uncompressed encoding is 0x04 || X (32B) || Y (32B). Address = keccak256(X||Y)[-20:].
  const pubBytes = pub.toRawBytes(false);
  const addr = keccak_256(pubBytes.slice(1)).slice(-20);
  if (!bytesEq(addr, expectedSigner)) {
    throw new ManifestError(
      `signer mismatch: recovered=0x${bytesToHex(addr)} expected=0x${bytesToHex(expectedSigner)}`
    );
  }

  const epoch = Number(fields["epoch"]);
  if (!Number.isFinite(epoch)) {
    throw new ManifestError(`invalid epoch: ${fields["epoch"]}`);
  }

  return {
    cluster: fields["cluster"]!,
    leaderInstance: fields["leader_instance"]!,
    leaderUrl: fields["leader_url"]!,
    epoch,
    validUntil,
  };
}
