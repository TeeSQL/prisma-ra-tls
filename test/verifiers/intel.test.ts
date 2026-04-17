import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { IntelApiVerifier } from "../../src/verifiers/intel.js";

// ---------------------------------------------------------------------------
// Mock jose at module level
// ---------------------------------------------------------------------------
vi.mock("jose", () => {
  return {
    decodeProtectedHeader: vi.fn(),
    createRemoteJWKSet: vi.fn().mockReturnValue(vi.fn()),
    jwtVerify: vi.fn(),
  };
});

import * as jose from "jose";

const FAKE_QUOTE = Buffer.from("fake-tdx-quote");

/** Build a minimal valid ITA-style JWT payload */
function makePayload(overrides: Record<string, unknown> = {}) {
  return {
    tdx_mrtd: "aabbccdd",
    tdx_rtmr0: "00112233",
    tdx_rtmr1: "44556677",
    tdx_rtmr2: "8899aabb",
    tdx_rtmr3: "ccddeeff",
    attester_tcb_status: "UpToDate",
    tdx_is_debuggable: false,
    ...overrides,
  };
}

/** Set up fetch + jose mocks to simulate a successful attestation */
function mockSuccess(payloadOverrides: Record<string, unknown> = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ token: "mock.jwt.token" }),
    })
  );
  vi.mocked(jose.decodeProtectedHeader).mockReturnValue({
    jku: "https://certs.trustauthority.intel.com/.well-known/jwks",
    kid: "test-kid-1",
    alg: "PS384",
  });
  vi.mocked(jose.jwtVerify).mockResolvedValue({
    payload: makePayload(payloadOverrides),
    protectedHeader: { alg: "PS384" },
  } as never);
}

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  delete process.env["INTEL_TRUST_AUTHORITY_API_KEY"];
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe("IntelApiVerifier constructor", () => {
  it("throws when no API key is provided and env var is unset", () => {
    expect(() => new IntelApiVerifier()).toThrow(
      "Intel Trust Authority API key required"
    );
  });

  it("reads API key from INTEL_TRUST_AUTHORITY_API_KEY env var", () => {
    process.env["INTEL_TRUST_AUTHORITY_API_KEY"] = "env-key-123";
    expect(() => new IntelApiVerifier()).not.toThrow();
  });

  it("uses provided apiKey option over env var", () => {
    process.env["INTEL_TRUST_AUTHORITY_API_KEY"] = "env-key";
    expect(() => new IntelApiVerifier({ apiKey: "opt-key" })).not.toThrow();
  });

  it("defaults to US base URL", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "k" });
    await v.verify(FAKE_QUOTE);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      expect.stringContaining("api.trustauthority.intel.com"),
      expect.anything()
    );
  });

  it("uses EU base URL when region is eu", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "k", region: "eu" });
    await v.verify(FAKE_QUOTE);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      expect.stringContaining("api.eu.trustauthority.intel.com"),
      expect.anything()
    );
  });

  it("uses custom baseUrl when provided", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "k", baseUrl: "https://my-proxy.example.com" });
    await v.verify(FAKE_QUOTE);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      expect.stringContaining("my-proxy.example.com"),
      expect.anything()
    );
  });
});

// ---------------------------------------------------------------------------
// fetchAttestationToken errors
// ---------------------------------------------------------------------------

describe("IntelApiVerifier.verify — ITA HTTP errors", () => {
  it("throws when ITA returns a non-ok status with a readable body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => "Unauthorized",
      })
    );
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("401");
  });

  it("throws when ITA returns non-ok status and body is unreadable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        text: async () => { throw new Error("network error"); },
      })
    );
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("503");
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("unreadable body");
  });

  it("throws when ITA response is missing the token field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ /* no token */ }),
      })
    );
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("missing token");
  });
});

// ---------------------------------------------------------------------------
// JWT validation errors
// ---------------------------------------------------------------------------

describe("IntelApiVerifier.verify — JWT validation", () => {
  it("throws when JWT header is missing jku", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ token: "t" }),
      })
    );
    vi.mocked(jose.decodeProtectedHeader).mockReturnValue({ kid: "k" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("missing jku");
  });

  it("throws when JWT header is missing kid", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ token: "t" }),
      })
    );
    vi.mocked(jose.decodeProtectedHeader).mockReturnValue({
      jku: "https://certs.trustauthority.intel.com/.well-known/jwks",
    });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("missing kid");
  });

  it("propagates jwtVerify errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ token: "t" }),
      })
    );
    vi.mocked(jose.decodeProtectedHeader).mockReturnValue({
      jku: "https://certs.trustauthority.intel.com/.well-known/jwks",
      kid: "k",
    });
    vi.mocked(jose.jwtVerify).mockRejectedValue(new Error("invalid signature"));
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("invalid signature");
  });
});

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

describe("IntelApiVerifier.verify — security checks", () => {
  it("succeeds with a valid UpToDate attestation", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "k" });
    const result = await v.verify(FAKE_QUOTE);
    expect(result.tcbStatus).toBe("UpToDate");
    expect(result.isDebugMode).toBe(false);
    expect(result.mrTd).toBe("aabbccdd");
  });

  it("accepts SWHardeningNeeded TCB status", async () => {
    mockSuccess({ attester_tcb_status: "SWHardeningNeeded" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).resolves.toMatchObject({
      tcbStatus: "SWHardeningNeeded",
    });
  });

  it("rejects OutOfDate TCB status", async () => {
    mockSuccess({ attester_tcb_status: "OutOfDate" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("OutOfDate");
  });

  it("rejects Revoked TCB status", async () => {
    mockSuccess({ attester_tcb_status: "Revoked" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("Revoked");
  });

  it("rejects debug mode by default (tdx_is_debuggable=true)", async () => {
    mockSuccess({ tdx_is_debuggable: true });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE, {})).rejects.toThrow("debug mode");
  });

  it("rejects debug mode via tdx_td_attributes_debug flag", async () => {
    mockSuccess({ tdx_is_debuggable: false, tdx_td_attributes_debug: true });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("debug mode");
  });

  it("allows debug mode when allowDebugMode is true", async () => {
    mockSuccess({ tdx_is_debuggable: true });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(
      v.verify(FAKE_QUOTE, { allowDebugMode: true })
    ).resolves.toMatchObject({ isDebugMode: true });
  });

  it("skips MRTD check when allowedMrTd is not set", async () => {
    mockSuccess({ tdx_mrtd: "any-mrtd-value" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE, {})).resolves.toBeDefined();
  });

  it("skips MRTD check when allowedMrTd is empty array", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE, { allowedMrTd: [] })).resolves.toBeDefined();
  });

  it("passes when MRTD is in allowlist (case-insensitive, 0x prefix stripped)", async () => {
    mockSuccess({ tdx_mrtd: "0xAABBCCDD" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(
      v.verify(FAKE_QUOTE, { allowedMrTd: ["aabbccdd"] })
    ).resolves.toMatchObject({ mrTd: "aabbccdd" });
  });

  it("rejects when MRTD is not in allowlist", async () => {
    mockSuccess({ tdx_mrtd: "deadbeef" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(
      v.verify(FAKE_QUOTE, { allowedMrTd: ["00000000"] })
    ).rejects.toThrow("deadbeef");
  });

  it("normalises lowercase MRTD in result", async () => {
    mockSuccess({ tdx_mrtd: "AABBCCDD" });
    const v = new IntelApiVerifier({ apiKey: "k" });
    const result = await v.verify(FAKE_QUOTE);
    expect(result.mrTd).toBe("aabbccdd");
  });

  it("handles missing MRTD claim gracefully (defaults to empty string)", async () => {
    mockSuccess({ tdx_mrtd: undefined });
    const v = new IntelApiVerifier({ apiKey: "k" });
    const result = await v.verify(FAKE_QUOTE);
    expect(result.mrTd).toBe("");
  });

  it("handles missing attester_tcb_status (defaults to Unknown → rejected)", async () => {
    mockSuccess({ attester_tcb_status: undefined });
    const v = new IntelApiVerifier({ apiKey: "k" });
    await expect(v.verify(FAKE_QUOTE)).rejects.toThrow("Unknown");
  });

  it("returns empty strings for missing rtmr claims", async () => {
    mockSuccess({
      tdx_rtmr0: undefined,
      tdx_rtmr1: undefined,
      tdx_rtmr2: undefined,
      tdx_rtmr3: undefined,
    });
    const v = new IntelApiVerifier({ apiKey: "k" });
    const result = await v.verify(FAKE_QUOTE);
    expect(result.rtmr0).toBe("");
    expect(result.rtmr1).toBe("");
    expect(result.rtmr2).toBe("");
    expect(result.rtmr3).toBe("");
  });

  it("sends quote as standard base64 in request body", async () => {
    mockSuccess();
    const quote = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const v = new IntelApiVerifier({ apiKey: "k" });
    await v.verify(quote);
    const body = JSON.parse(
      (vi.mocked(fetch).mock.calls[0]?.[1] as RequestInit)?.body as string
    ) as { quote: string };
    expect(body.quote).toBe(quote.toString("base64"));
  });

  it("sets x-api-key header on the ITA request", async () => {
    mockSuccess();
    const v = new IntelApiVerifier({ apiKey: "my-secret-key" });
    await v.verify(FAKE_QUOTE);
    const headers = (vi.mocked(fetch).mock.calls[0]?.[1] as RequestInit)
      ?.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("my-secret-key");
  });
});
