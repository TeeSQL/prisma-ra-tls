import * as jose from "jose";
import type { RaTlsVerifier, VerificationResult, VerifyOptions } from "../types.js";

const ITA_BASE_US = "https://api.trustauthority.intel.com";
const ITA_BASE_EU = "https://api.eu.trustauthority.intel.com";

// TCB statuses we consider acceptable.
// "OutOfDate" and "Revoked" are hard failures.
// "ConfigurationNeeded" and "ConfigurationAndSWHardeningNeeded" are borderline —
// we reject them by default but users can extend this set via a custom verifier.
const ACCEPTABLE_TCB_STATUSES = new Set(["UpToDate", "SWHardeningNeeded"]);

interface AttestationTokenClaims {
  tdx_mrtd?: string;
  tdx_rtmr0?: string;
  tdx_rtmr1?: string;
  tdx_rtmr2?: string;
  tdx_rtmr3?: string;
  attester_tcb_status?: string;
  tdx_is_debuggable?: boolean;
  tdx_td_attributes_debug?: boolean;
  [key: string]: unknown;
}

export interface IntelApiVerifierOptions {
  /**
   * Intel Trust Authority API key.
   * Falls back to the INTEL_TRUST_AUTHORITY_API_KEY environment variable.
   */
  apiKey?: string;
  /**
   * API region. Default: "us".
   * Use "eu" for EU-resident workloads.
   */
  region?: "us" | "eu";
  /**
   * Override the full base URL. Useful for proxies or testing against
   * the ITA staging environment.
   */
  baseUrl?: string;
}

/**
 * Verifies TDX attestation quotes via the Intel Trust Authority REST API.
 *
 * Intel Trust Authority is a free service. Register at:
 * https://portal.trustauthority.intel.com
 */
export class IntelApiVerifier implements RaTlsVerifier {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(options: IntelApiVerifierOptions = {}) {
    const apiKey = options.apiKey ?? process.env["INTEL_TRUST_AUTHORITY_API_KEY"];
    if (!apiKey) {
      throw new Error(
        "Intel Trust Authority API key required. " +
          "Pass { apiKey } option or set INTEL_TRUST_AUTHORITY_API_KEY env var. " +
          "Register at https://portal.trustauthority.intel.com"
      );
    }
    this.apiKey = apiKey;
    this.baseUrl =
      options.baseUrl ?? (options.region === "eu" ? ITA_BASE_EU : ITA_BASE_US);
  }

  async verify(quote: Buffer, options: VerifyOptions = {}): Promise<VerificationResult> {
    const token = await this.fetchAttestationToken(quote);
    return this.validateToken(token, options);
  }

  private async fetchAttestationToken(quote: Buffer): Promise<string> {
    const response = await fetch(`${this.baseUrl}/appraisal/v2/attest`, {
      method: "POST",
      headers: {
        "x-api-key": this.apiKey,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        // Base64-encoded raw TDX quote bytes (RFC 4648, standard, with padding)
        quote: quote.toString("base64"),
        // PS384 is Intel's default and preferred algorithm
        token_signing_alg: "PS384",
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "(unreadable body)");
      throw new Error(
        `Intel Trust Authority returned ${response.status}: ${body}`
      );
    }

    const data = (await response.json()) as { token?: string };
    if (!data.token) {
      throw new Error("Intel Trust Authority response missing token field");
    }
    return data.token;
  }

  private async validateToken(
    token: string,
    options: VerifyOptions
  ): Promise<VerificationResult> {
    // The JWT header contains jku (JWKS URL) and kid (key ID).
    // We use them to fetch Intel's public key and verify the signature.
    const header = jose.decodeProtectedHeader(token);

    if (typeof header["jku"] !== "string") {
      throw new Error("Attestation token missing jku header");
    }
    if (!header["kid"]) {
      throw new Error("Attestation token missing kid header");
    }

    const jwks = jose.createRemoteJWKSet(new URL(header["jku"]));
    const { payload } = await jose.jwtVerify(token, jwks, {
      algorithms: ["PS384", "RS256"],
    });

    const claims = payload as AttestationTokenClaims;

    // --- Security checks ---

    const isDebugMode =
      claims["tdx_is_debuggable"] === true ||
      claims["tdx_td_attributes_debug"] === true;

    if (isDebugMode && !(options.allowDebugMode ?? false)) {
      throw new Error(
        "TDX TD is in debug mode — connection refused. " +
          "Debug TDs have no confidentiality guarantees. " +
          "Set allowDebugMode: true to override (not recommended for production)."
      );
    }

    const tcbStatus = claims["attester_tcb_status"] ?? "Unknown";
    if (!ACCEPTABLE_TCB_STATUSES.has(tcbStatus)) {
      throw new Error(
        `Unacceptable TCB status: "${tcbStatus}". ` +
          `Acceptable statuses: ${[...ACCEPTABLE_TCB_STATUSES].join(", ")}. ` +
          "Update the platform firmware/microcode or check Intel's advisory."
      );
    }

    const mrTd = (claims["tdx_mrtd"] ?? "").toLowerCase().replace(/^0x/, "");

    if (options.allowedMrTd && options.allowedMrTd.length > 0) {
      const allowlist = options.allowedMrTd.map((s) =>
        s.toLowerCase().replace(/^0x/, "")
      );
      if (!allowlist.includes(mrTd)) {
        throw new Error(
          `MRTD "${mrTd}" is not in the allowlist. ` +
            "Update allowedMrTd if you intentionally upgraded the CVM image."
        );
      }
    }

    return {
      mrTd,
      rtmr0: (claims["tdx_rtmr0"] ?? "").toLowerCase(),
      rtmr1: (claims["tdx_rtmr1"] ?? "").toLowerCase(),
      rtmr2: (claims["tdx_rtmr2"] ?? "").toLowerCase(),
      rtmr3: (claims["tdx_rtmr3"] ?? "").toLowerCase(),
      tcbStatus,
      isDebugMode,
    };
  }
}
