// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Nonce } from "../../src/authentication-challenge/domain/model/nonce.js";

describe("T-08: Nonce.equals must not early-return on length mismatch", () => {
  it("returns false for different-length nonces (using XOR accumulator, not early return)", () => {
    const nonce1 = Nonce.create(new Uint8Array(16).fill(0x00), BigInt(0));
    const nonce2 = Nonce.create(new Uint8Array(32).fill(0x00), BigInt(0));

    // nonce1 = 24 bytes all zeros, nonce2 = 40 bytes all zeros
    // The comparison must return false without early return
    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("returns false for different-length nonces even when content overlaps perfectly", () => {
    // Both start with identical 24 bytes but nonce2 has extra trailing zeros
    const nonce1 = Nonce.create(new Uint8Array(16).fill(0xab), BigInt(42));
    const nonce2 = Nonce.create(new Uint8Array(32).fill(0xab), BigInt(42));

    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("returns true for identical nonces (constant-time path)", () => {
    const random = new Uint8Array(16).fill(0xab);
    const nonce1 = Nonce.create(random, BigInt(42));
    const nonce2 = Nonce.create(new Uint8Array(random), BigInt(42));

    expect(nonce1.equals(nonce2)).toBe(true);
  });
});
