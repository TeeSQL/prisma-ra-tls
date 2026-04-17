import { X509Certificate } from "@peculiar/x509";

// dstack RA-TLS X.509 extension OIDs (Phala PEN: 62397)
// Source: https://github.com/Dstack-TEE/dstack/blob/master/ra-tls/src/oids.rs
const OID_TDX_QUOTE = "1.3.6.1.4.1.62397.1.1"; // raw TDX quote bytes
const OID_ATTESTATION = "1.3.6.1.4.1.62397.1.8"; // SCALE-encoded VersionedAttestation (v1.1)

/**
 * Parse a DER-encoded OCTET STRING and return its contents.
 *
 * dstack encodes extension payloads as DER OCTET STRING { payload }, so
 * after @peculiar/x509 unwraps the outer extnValue OCTET STRING, we still
 * need to strip one more DER OCTET STRING tag+length to reach the raw bytes.
 *
 * @internal exported for testing
 */
export function _stripOctetStringWrapper(der: Buffer): Buffer {
  if (der.length < 2 || der[0] !== 0x04) {
    // Not a DER OCTET STRING — return as-is (defensive)
    return der;
  }
  let offset = 1;
  // Safe: der.length >= 2 is guaranteed by the check above
  const firstLenByte = der[offset] as number;
  let length: number;
  if (firstLenByte < 0x80) {
    length = firstLenByte;
    offset++;
  } else {
    const numLenBytes = firstLenByte & 0x7f;
    offset++;
    length = 0;
    for (let i = 0; i < numLenBytes; i++) {
      const b = der[offset + i];
      if (b === undefined) throw new Error("Truncated OCTET STRING length field");
      length = (length << 8) | b;
    }
    offset += numLenBytes;
  }
  return der.subarray(offset, offset + length);
}

/**
 * Extract a raw TDX quote from a dstack RA-TLS DER-encoded X.509 certificate.
 *
 * Tries the legacy OID (1.3.6.1.4.1.62397.1.1) first — raw quote bytes,
 * trivial to parse. Falls back to the current OID (1.3.6.1.4.1.62397.1.8)
 * which carries a SCALE-encoded VersionedAttestation; in that case we strip
 * the V0 enum tag byte and return the remainder (full SCALE decode in v1.1).
 *
 * Returns null if neither extension is present (e.g. non-RA-TLS certificate).
 */
export function extractTdxQuote(derCert: Buffer): Buffer | null {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(derCert);
  } catch {
    return null;
  }

  // --- Legacy OID: raw TDX quote bytes ---
  const legacyExt = cert.getExtension(OID_TDX_QUOTE);
  if (legacyExt) {
    try {
      return _stripOctetStringWrapper(Buffer.from(legacyExt.value));
    } catch {
      // Malformed extension value — fall through to current OID
    }
  }

  // --- Current OID: SCALE-encoded VersionedAttestation ---
  // Layout: [variant_u8=0x00][attestation_bytes...]
  // We return the attestation_bytes slice. Full SCALE decode in v1.1.
  const currentExt = cert.getExtension(OID_ATTESTATION);
  if (currentExt) {
    try {
      const payload = _stripOctetStringWrapper(Buffer.from(currentExt.value));
      if (payload.length > 1 && payload[0] === 0x00) {
        return payload.subarray(1);
      }
    } catch {
      // Malformed extension value — fall through
    }
  }

  return null;
}
