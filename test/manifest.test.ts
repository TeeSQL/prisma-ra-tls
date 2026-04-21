/**
 * Manifest verifier unit tests.
 *
 * The canonical body format is ALSO tested in:
 *   - crates/dns-controller/src/manifest.rs (Rust writer)
 *   - open-source/psycopg-ra-tls/tests/test_manifest.py (Python verifier)
 *
 * All three implementations MUST agree byte-for-byte; the golden-string
 * test below pins the exact pre-signing bytes so a drift between any
 * surfaces as a failure in at least two test suites.
 */

import { describe, it, expect } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

import {
  type Manifest,
  ManifestError,
  canonicalBody,
  parseAndVerify,
} from "../src/manifest.js";

const FIXTURE_PRIVATE_KEY = new Uint8Array(32).fill(0x11);

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "0x";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
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

function fixtureAddress(): Uint8Array {
  const pub = secp256k1.getPublicKey(FIXTURE_PRIVATE_KEY, false); // 0x04||X||Y
  return keccak_256(pub.slice(1)).slice(-20);
}

function signEip191(body: string): string {
  const encoder = new TextEncoder();
  const prefix = encoder.encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const digest = keccak_256(concat(prefix, encoder.encode(body)));
  const sig = secp256k1.sign(digest, FIXTURE_PRIVATE_KEY);
  const r = sig.r.toString(16).padStart(64, "0");
  const s = sig.s.toString(16).padStart(64, "0");
  const v = (27 + sig.recovery).toString(16).padStart(2, "0");
  return `0x${r}${s}${v}`;
}

function fixtureManifest(): Manifest {
  return {
    cluster: "0xbd32b609057a1a4569558a571d535c8f1212b097",
    leaderInstance: "ea23198e3419ebbb240571a29d0112d9bcbe69c0",
    leaderUrl:
      "https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network",
    epoch: 42,
    validUntil: Math.floor(Date.now() / 1000) + 3600,
  };
}

describe("canonicalBody", () => {
  it("matches the Rust/Python golden string exactly", () => {
    const m: Manifest = {
      cluster: "0xbd32b609057a1a4569558a571d535c8f1212b097",
      leaderInstance: "ea23198e3419ebbb240571a29d0112d9bcbe69c0",
      leaderUrl:
        "https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network",
      epoch: 42,
      validUntil: 1713312000,
    };
    const expected =
      "cluster=0xbd32b609057a1a4569558a571d535c8f1212b097;" +
      "epoch=42;" +
      "leader_instance=ea23198e3419ebbb240571a29d0112d9bcbe69c0;" +
      "leader_url=https://ea23198e3419ebbb240571a29d0112d9bcbe69c0-5433.dstack-base-prod9.phala.network;" +
      "v=1;" +
      "valid_until=1713312000";
    expect(canonicalBody(m)).toBe(expected);
  });
});

describe("parseAndVerify", () => {
  it("accepts a correctly signed manifest", () => {
    const m = fixtureManifest();
    const body = canonicalBody(m);
    const sig = signEip191(body);
    const txt = `${body};sig=${sig}`;
    const parsed = parseAndVerify(txt, fixtureAddress());
    expect(parsed.cluster).toBe(m.cluster);
    expect(parsed.epoch).toBe(m.epoch);
    expect(parsed.leaderUrl).toBe(m.leaderUrl);
  });

  it("rejects the wrong signer", () => {
    const m = fixtureManifest();
    const body = canonicalBody(m);
    const txt = `${body};sig=${signEip191(body)}`;
    expect(() => parseAndVerify(txt, new Uint8Array(20))).toThrow(/signer mismatch/);
  });

  it("rejects a tampered body", () => {
    const m = fixtureManifest();
    const body = canonicalBody(m);
    const sig = signEip191(body);
    const tampered = canonicalBody({ ...m, leaderUrl: "https://evil.example.com" });
    const txt = `${tampered};sig=${sig}`;
    expect(() => parseAndVerify(txt, fixtureAddress())).toThrow(/signer mismatch/);
  });

  it("rejects an expired manifest", () => {
    const m: Manifest = { ...fixtureManifest(), validUntil: 1000 };
    const body = canonicalBody(m);
    const txt = `${body};sig=${signEip191(body)}`;
    expect(() => parseAndVerify(txt, fixtureAddress(), { now: 2000 })).toThrow(/expired/);
  });

  it("rejects an unsupported version", () => {
    const m = fixtureManifest();
    const body = canonicalBody(m).replace("v=1", "v=2");
    const txt = `${body};sig=${signEip191(body)}`;
    expect(() => parseAndVerify(txt, fixtureAddress())).toThrow(
      /unsupported manifest version/
    );
  });

  it("rejects a short sig", () => {
    const body = canonicalBody(fixtureManifest());
    const txt = `${body};sig=0xdeadbeef`;
    expect(() => parseAndVerify(txt, fixtureAddress())).toThrow(/sig must be 65 bytes/);
  });

  it("rejects a missing sig", () => {
    const body = canonicalBody(fixtureManifest());
    expect(() => parseAndVerify(body, fixtureAddress())).toThrow(/missing sig field/);
  });

  it("requires a 20-byte expected signer", () => {
    const m = fixtureManifest();
    const txt = `${canonicalBody(m)};sig=${signEip191(canonicalBody(m))}`;
    expect(() => parseAndVerify(txt, new Uint8Array(19))).toThrow(/must be 20 bytes/);
  });
});

// Silence unused-helper linter warnings for test helpers retained for
// debugging signature round-trips.
void hexToBytes;
void bytesToHex;
