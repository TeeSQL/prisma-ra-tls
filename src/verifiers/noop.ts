import type { RaTlsVerifier, VerificationResult, VerifyOptions } from "../types.js";

const MOCK_RESULT: VerificationResult = {
  mrTd: "0".repeat(96),
  rtmr0: "0".repeat(96),
  rtmr1: "0".repeat(96),
  rtmr2: "0".repeat(96),
  rtmr3: "0".repeat(96),
  tcbStatus: "UpToDate",
  isDebugMode: false,
};

/**
 * No-op verifier that skips all attestation checks.
 *
 * Use this in tests, local development, or when DSTACK_SIMULATOR_ENDPOINT
 * is set. Never use in production.
 */
export class NoopVerifier implements RaTlsVerifier {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async verify(_quote: Buffer, _options: VerifyOptions = {}): Promise<VerificationResult> {
    return { ...MOCK_RESULT };
  }
}
