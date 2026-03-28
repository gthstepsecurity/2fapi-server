// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RngHealthChecker } from "../../../src/shared/rng-health-checker.js";
import { HedgedNonceGenerator } from "../../../src/zk-verification/infrastructure/adapter/outgoing/hedged-nonce-generator.js";

describe("RngHealthChecker", () => {
  const checker = new RngHealthChecker();

  it("accepts normal random bytes with sufficient entropy", () => {
    // 32 bytes with high diversity
    const randomBytes = new Uint8Array([
      0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
      0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ]);
    const result = checker.validate(randomBytes);
    expect(result.healthy).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("rejects all-zeros random bytes", () => {
    const allZeros = new Uint8Array(32).fill(0x00);
    const result = checker.validate(allZeros);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_health_failure");
  });

  it("rejects all-ones (0xFF) random bytes", () => {
    const allOnes = new Uint8Array(32).fill(0xff);
    const result = checker.validate(allOnes);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("rejects low-entropy random (all same byte 0xAB)", () => {
    const lowEntropy = new Uint8Array(32).fill(0xab);
    const result = checker.validate(lowEntropy);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("rejects bytes with fewer than 4 distinct values", () => {
    // Only 3 distinct byte values
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = [0x01, 0x02, 0x03][i % 3]!;
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("rejects bytes with only 4 distinct values (threshold raised to 16)", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = [0x01, 0x02, 0x03, 0x04][i % 4]!;
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("accepts bytes with exactly 16 distinct values", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = i % 16;
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(true);
  });
});

describe("HedgedNonceGenerator", () => {
  it("produces a nonce from hedged construction: H(secret || counter || random)", () => {
    const generator = new HedgedNonceGenerator("test-secret");

    const randomBytes = new Uint8Array([
      0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
      0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ]);

    const nonce = generator.deriveNonce(randomBytes, 0);
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(32);
  });

  it("produces different nonces with same random but different counter", () => {
    const generator = new HedgedNonceGenerator("test-secret");

    const sameRandom = new Uint8Array(32).fill(0x42);

    const nonce1 = generator.deriveNonce(sameRandom, 1);
    const nonce2 = generator.deriveNonce(sameRandom, 2);

    expect(nonce1).not.toEqual(nonce2);
  });

  it("produces different nonces with same counter but different random", () => {
    const generator = new HedgedNonceGenerator("test-secret");

    const random1 = new Uint8Array(32).fill(0x01);
    const random2 = new Uint8Array(32).fill(0x02);

    const nonce1 = generator.deriveNonce(random1, 1);
    const nonce2 = generator.deriveNonce(random2, 1);

    expect(nonce1).not.toEqual(nonce2);
  });

  it("produces different nonces with same inputs but different secret context", () => {
    const generator1 = new HedgedNonceGenerator("secret-a");
    const generator2 = new HedgedNonceGenerator("secret-b");

    const sameRandom = new Uint8Array(32).fill(0x99);

    const nonce1 = generator1.deriveNonce(sameRandom, 1);
    const nonce2 = generator2.deriveNonce(sameRandom, 1);

    expect(nonce1).not.toEqual(nonce2);
  });

  it("produces deterministic output: same inputs always yield same nonce", () => {
    const generator = new HedgedNonceGenerator("deterministic-secret");
    const randomBytes = new Uint8Array(32).fill(0xab);

    const nonce1 = generator.deriveNonce(randomBytes, 42);
    const nonce2 = generator.deriveNonce(randomBytes, 42);

    expect(nonce1).toEqual(nonce2);
  });

  it("handles degraded mode: all-zero random still produces valid nonce via counter", () => {
    const generator = new HedgedNonceGenerator("fallback-secret");
    const zeroRandom = new Uint8Array(32).fill(0x00);

    // Counter provides uniqueness even when random is broken
    const nonce1 = generator.deriveNonce(zeroRandom, 1);
    const nonce2 = generator.deriveNonce(zeroRandom, 2);

    expect(nonce1.length).toBe(32);
    expect(nonce2.length).toBe(32);
    expect(nonce1).not.toEqual(nonce2);
  });
});
