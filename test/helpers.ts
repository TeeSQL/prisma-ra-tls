import { X509CertificateGenerator, Extension } from "@peculiar/x509";

/**
 * Build a DER OCTET STRING wrapping the given payload.
 * Used to craft the inner wrapper that dstack puts around extension payloads.
 */
export function makeDerOctetString(payload: Buffer): Buffer {
  const len = payload.length;
  if (len < 0x80) {
    return Buffer.concat([Buffer.from([0x04, len]), payload]);
  }
  if (len < 0x100) {
    return Buffer.concat([Buffer.from([0x04, 0x81, len]), payload]);
  }
  return Buffer.concat([
    Buffer.from([0x04, 0x82, (len >> 8) & 0xff, len & 0xff]),
    payload,
  ]);
}

/**
 * Generate a self-signed DER-encoded X.509 certificate with the given
 * custom X.509 extensions. Uses ECDSA P-256 (available in Node 18+).
 */
export async function generateCertWithExtensions(
  exts: Array<{ oid: string; value: Buffer }>
): Promise<Buffer> {
  const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
  const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=test-ra-tls",
    notBefore: new Date("2025-01-01"),
    notAfter: new Date("2030-01-01"),
    signingAlgorithm: alg,
    keys,
    extensions: exts.map(({ oid, value }) => new Extension(oid, false, value)),
  });

  return Buffer.from(cert.rawData);
}

/** Generate a minimal self-signed cert with no custom extensions. */
export async function generatePlainCert(): Promise<Buffer> {
  return generateCertWithExtensions([]);
}
