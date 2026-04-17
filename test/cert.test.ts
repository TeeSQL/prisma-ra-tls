import { describe, it, expect, vi, beforeEach } from "vitest";
import { _stripOctetStringWrapper, extractTdxQuote } from "../src/cert.js";
import {
  makeDerOctetString,
  generateCertWithExtensions,
  generatePlainCert,
} from "./helpers.js";

const OID_TDX_QUOTE = "1.3.6.1.4.1.62397.1.1";
const OID_ATTESTATION = "1.3.6.1.4.1.62397.1.8";

// ---------------------------------------------------------------------------
// _stripOctetStringWrapper — direct unit tests
// ---------------------------------------------------------------------------

describe("_stripOctetStringWrapper", () => {
  it("returns buffer as-is when too short (length 0)", () => {
    const buf = Buffer.alloc(0);
    expect(_stripOctetStringWrapper(buf)).toBe(buf);
  });

  it("returns buffer as-is when too short (length 1)", () => {
    const buf = Buffer.from([0x04]);
    expect(_stripOctetStringWrapper(buf)).toBe(buf);
  });

  it("returns buffer as-is when first byte is not OCTET STRING tag", () => {
    const buf = Buffer.from([0x05, 0x03, 0x01, 0x02, 0x03]);
    expect(_stripOctetStringWrapper(buf)).toBe(buf);
  });

  it("strips short-form length OCTET STRING (length < 128)", () => {
    const payload = Buffer.from("hello world");
    const der = makeDerOctetString(payload);
    expect(der[0]).toBe(0x04);
    expect(der[1]).toBe(payload.length); // short form
    const result = _stripOctetStringWrapper(der);
    expect(result).toEqual(payload);
  });

  it("strips long-form single-byte length OCTET STRING (0x81 prefix)", () => {
    // Payload of exactly 128 bytes triggers 0x81 length encoding
    const payload = Buffer.alloc(128, 0xab);
    const der = makeDerOctetString(payload);
    expect(der[1]).toBe(0x81); // long form, 1 extra byte
    const result = _stripOctetStringWrapper(der);
    expect(result).toEqual(payload);
  });

  it("strips long-form two-byte length OCTET STRING (0x82 prefix)", () => {
    // Payload of 256 bytes triggers 0x82 length encoding
    const payload = Buffer.alloc(256, 0xcd);
    const der = makeDerOctetString(payload);
    expect(der[1]).toBe(0x82); // long form, 2 extra bytes
    const result = _stripOctetStringWrapper(der);
    expect(result).toEqual(payload);
  });

  it("throws on truncated multi-byte length field", () => {
    // 0x04 = OCTET STRING, 0x82 = 2 more length bytes, but only 1 follows
    const truncated = Buffer.from([0x04, 0x82, 0xff]);
    expect(() => _stripOctetStringWrapper(truncated)).toThrow(
      "Truncated OCTET STRING length field"
    );
  });
});

// ---------------------------------------------------------------------------
// extractTdxQuote
// ---------------------------------------------------------------------------

describe("extractTdxQuote", () => {
  it("returns null for completely invalid DER input", () => {
    expect(extractTdxQuote(Buffer.from("not-a-cert"))).toBeNull();
  });

  it("returns null for a plain cert with no RA-TLS extensions", async () => {
    const certDer = await generatePlainCert();
    expect(extractTdxQuote(certDer)).toBeNull();
  });

  it("extracts quote from legacy OID (raw TDX quote bytes)", async () => {
    const fakeQuote = Buffer.from("fake-tdx-quote-bytes-0123456789");
    const certDer = await generateCertWithExtensions([
      { oid: OID_TDX_QUOTE, value: makeDerOctetString(fakeQuote) },
    ]);
    const result = extractTdxQuote(certDer);
    expect(result).toEqual(fakeQuote);
  });

  it("falls through legacy OID and extracts from current OID (V0 SCALE)", async () => {
    const fakeAttestation = Buffer.from("scale-encoded-attestation-data");
    // current OID payload: OCTET STRING { 0x00 || attestation_bytes }
    const scalePayload = Buffer.concat([Buffer.from([0x00]), fakeAttestation]);
    const certDer = await generateCertWithExtensions([
      { oid: OID_ATTESTATION, value: makeDerOctetString(scalePayload) },
    ]);
    const result = extractTdxQuote(certDer);
    expect(result).toEqual(fakeAttestation);
  });

  it("returns null for current OID with non-V0 enum variant", async () => {
    // First byte is 0x01 (V1), not 0x00 — not yet supported
    const v1Payload = Buffer.from([0x01, 0xde, 0xad, 0xbe, 0xef]);
    const certDer = await generateCertWithExtensions([
      { oid: OID_ATTESTATION, value: makeDerOctetString(v1Payload) },
    ]);
    expect(extractTdxQuote(certDer)).toBeNull();
  });

  it("returns null for current OID with single-byte payload (length <= 1)", async () => {
    // payload.length is 1 so `payload.length > 1` fails
    const singleByte = Buffer.from([0x00]);
    const certDer = await generateCertWithExtensions([
      { oid: OID_ATTESTATION, value: makeDerOctetString(singleByte) },
    ]);
    expect(extractTdxQuote(certDer)).toBeNull();
  });

  it("falls through legacy OID when its value is malformed, tries current OID", async () => {
    // Legacy OID value triggers the truncated-length throw in stripOctetStringWrapper.
    // Current OID has a valid V0 payload — should be returned.
    const fakeAttestation = Buffer.from("attestation-after-legacy-fallback");
    const scalePayload = Buffer.concat([Buffer.from([0x00]), fakeAttestation]);

    // Malformed legacy: 0x04 0x82 0xff — claims 2 length bytes but only 1 present
    const malformedLegacy = new Uint8Array([0x04, 0x82, 0xff]);

    // We need the cert to have BOTH extensions. Use @peculiar/x509 with manual
    // raw extension values by mocking the getExtension return values.
    // It's simpler to mock X509Certificate here than to hand-craft DER.
    const { X509Certificate } = await import("@peculiar/x509");
    const scaleBytes = new Uint8Array(makeDerOctetString(scalePayload));
    const mockGetExt = vi.fn().mockImplementation((oid: string) => {
      if (oid === OID_TDX_QUOTE)
        return { value: malformedLegacy.buffer as ArrayBuffer };
      if (oid === OID_ATTESTATION)
        return { value: scaleBytes.buffer as ArrayBuffer };
      return null;
    });
    const MockCert = vi.spyOn({ X509Certificate }, "X509Certificate");
    // Use vi.mock for the module-level import instead
    vi.spyOn(X509Certificate.prototype, "getExtension").mockImplementation(
      mockGetExt
    );

    const certDer = await generatePlainCert(); // any valid DER cert
    const result = extractTdxQuote(certDer);
    expect(result).toEqual(fakeAttestation);

    vi.restoreAllMocks();
    MockCert.mockRestore();
  });

  it("falls through both OIDs when current OID value is malformed", async () => {
    const { X509Certificate } = await import("@peculiar/x509");
    const malformed = new Uint8Array([0x04, 0x82, 0xff]);

    vi.spyOn(X509Certificate.prototype, "getExtension").mockImplementation(
      (oid: string) => {
        if (oid === OID_TDX_QUOTE)
          return { value: malformed.buffer as ArrayBuffer };
        if (oid === OID_ATTESTATION)
          return { value: malformed.buffer as ArrayBuffer };
        return null;
      }
    );

    const certDer = await generatePlainCert();
    expect(extractTdxQuote(certDer)).toBeNull();
    vi.restoreAllMocks();
  });
});
