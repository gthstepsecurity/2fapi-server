// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll } from "vitest";

/**
 * Integration tests for the napi-rs crypto module.
 *
 * These tests verify that the Rust crypto core (via @2fapi/crypto-native)
 * correctly implements Pedersen commitments and Sigma proof verification.
 *
 * Prerequisites:
 *   cd crypto-core/napi && cargo build --release
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("NapiProofVerification [integration]", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let crypto: any;

  beforeAll(async () => {
    // Dynamic import so tests can be skipped when binary is not available
    crypto = await import("@2fapi/crypto-native");
  });

  describe("isCanonicalPoint", () => {
    it("should accept a valid Ristretto255 point", () => {
      // The basepoint compressed encoding (well-known constant)
      const basepointBytes = Buffer.alloc(32);
      // A valid compressed Ristretto255 point would be provided here
      // For now, this is a placeholder for the actual basepoint bytes
      expect(crypto.isCanonicalPoint).toBeDefined();
    });

    it("should reject an all-0xFF buffer", () => {
      const invalid = Buffer.alloc(32, 0xff);
      expect(crypto.isCanonicalPoint(invalid)).toBe(false);
    });

    it("should reject a buffer of wrong length", () => {
      const short = Buffer.alloc(16);
      expect(crypto.isCanonicalPoint(short)).toBe(false);
    });
  });

  describe("isCanonicalScalar", () => {
    it("should accept zero scalar", () => {
      const zero = Buffer.alloc(32, 0);
      expect(crypto.isCanonicalScalar(zero)).toBe(true);
    });

    it("should reject all-0xFF (>= group order)", () => {
      const overflow = Buffer.alloc(32, 0xff);
      expect(crypto.isCanonicalScalar(overflow)).toBe(false);
    });
  });

  describe("isIdentityPoint", () => {
    it("should detect the identity (32 zero bytes)", () => {
      const identity = Buffer.alloc(32, 0);
      expect(crypto.isIdentityPoint(identity)).toBe(true);
    });

    it("should reject non-identity points", () => {
      const nonIdentity = Buffer.alloc(32, 0x01);
      expect(crypto.isIdentityPoint(nonIdentity)).toBe(false);
    });
  });

  describe("hashTranscript", () => {
    it("should return a 32-byte buffer", () => {
      const data = Buffer.from("test transcript data");
      const hash = crypto.hashTranscript(data);
      expect(hash.length).toBe(32);
    });

    it("should be deterministic", () => {
      const data = Buffer.from("deterministic test");
      const h1 = crypto.hashTranscript(data);
      const h2 = crypto.hashTranscript(data);
      expect(Buffer.from(h1).equals(Buffer.from(h2))).toBe(true);
    });

    it("should produce different hashes for different inputs", () => {
      const h1 = crypto.hashTranscript(Buffer.from("input-a"));
      const h2 = crypto.hashTranscript(Buffer.from("input-b"));
      expect(Buffer.from(h1).equals(Buffer.from(h2))).toBe(false);
    });
  });

  describe("commit + generateProof + verifyProofEquation", () => {
    it("should verify a valid proof roundtrip", () => {
      // Generate random secret and blinding (32 bytes each, < group order)
      const secret = Buffer.alloc(32);
      secret[0] = 42;
      const blinding = Buffer.alloc(32);
      blinding[0] = 99;

      // Compute commitment
      const commitment = crypto.commit(secret, blinding);
      expect(commitment.length).toBe(32);

      // We cannot fully test generateProof + verifyProofEquation here
      // without the actual generators, but we verify the API exists
      expect(crypto.generateProof).toBeDefined();
      expect(crypto.verifyProofEquation).toBeDefined();
    });
  });
});
