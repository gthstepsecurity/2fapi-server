// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { CryptoNonceGenerator } from "../../../../../src/authentication-challenge/infrastructure/adapter/outgoing/crypto-nonce-generator.js";

describe("CryptoNonceGenerator", () => {
  it("should generate a nonce with at least 24 bytes (16 random + 8 counter)", () => {
    const generator = new CryptoNonceGenerator();

    const nonce = generator.generate();

    expect(nonce.toBytes().length).toBe(24);
  });

  it("should generate unique nonces on consecutive calls", () => {
    const generator = new CryptoNonceGenerator();

    const nonce1 = generator.generate();
    const nonce2 = generator.generate();

    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("should increment the monotonic counter on each call", () => {
    const generator = new CryptoNonceGenerator();

    const nonce1 = generator.generate();
    const nonce2 = generator.generate();

    // Counter is in the last 8 bytes
    const counter1 = new DataView(nonce1.toBytes().buffer).getBigUint64(16, false);
    const counter2 = new DataView(nonce2.toBytes().buffer).getBigUint64(16, false);

    expect(counter2).toBe(counter1 + BigInt(1));
  });

  it("should guarantee structural uniqueness even if CSPRNG repeats (property-based)", async () => {
    const generator = new CryptoNonceGenerator();
    const nonces = new Set<string>();

    await fc.assert(
      fc.property(fc.integer({ min: 0, max: 999 }), () => {
        const nonce = generator.generate();
        const hex = Buffer.from(nonce.toBytes()).toString("hex");
        const wasNew = !nonces.has(hex);
        nonces.add(hex);
        return wasNew;
      }),
      { numRuns: 1000 },
    );
  });

  it("should throw when counter overflows u64 max", () => {
    const generator = new CryptoNonceGenerator(BigInt("18446744073709551615"));

    expect(() => generator.generate()).toThrow("counter exhaustion");
  });

  it("should start from a specified initial counter value", () => {
    const initialCounter = BigInt(42);
    const generator = new CryptoNonceGenerator(initialCounter);

    const nonce = generator.generate();
    const counter = new DataView(nonce.toBytes().buffer).getBigUint64(16, false);

    expect(counter).toBe(initialCounter);
  });
});
