import { describe, it, expect } from "vitest";
import { NoopVerifier } from "../../src/verifiers/noop.js";

describe("NoopVerifier", () => {
  const verifier = new NoopVerifier();
  const fakeQuote = Buffer.from("any-bytes");

  it("returns a VerificationResult without throwing", async () => {
    const result = await verifier.verify(fakeQuote, {});
    expect(result).toMatchObject({
      tcbStatus: "UpToDate",
      isDebugMode: false,
    });
  });

  it("mrTd and all RTMRs are all-zero strings", async () => {
    const result = await verifier.verify(fakeQuote);
    expect(result.mrTd).toBe("0".repeat(96));
    expect(result.rtmr0).toBe("0".repeat(96));
    expect(result.rtmr1).toBe("0".repeat(96));
    expect(result.rtmr2).toBe("0".repeat(96));
    expect(result.rtmr3).toBe("0".repeat(96));
  });

  it("returns an independent copy each call (no shared mutable state)", async () => {
    const a = await verifier.verify(fakeQuote);
    const b = await verifier.verify(fakeQuote);
    expect(a).not.toBe(b);
  });

  it("accepts verify() with no options argument", async () => {
    await expect(verifier.verify(fakeQuote)).resolves.toBeDefined();
  });
});
