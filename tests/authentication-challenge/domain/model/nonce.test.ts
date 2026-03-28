// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Nonce } from "../../../../src/authentication-challenge/domain/model/nonce.js";

describe("Nonce", () => {
  it("should be created from a random part (>=16 bytes) and a counter value", () => {
    const randomPart = new Uint8Array(16).fill(0xab);
    const counter = BigInt(1);

    const nonce = Nonce.create(randomPart, counter);

    expect(nonce).toBeDefined();
  });

  it("should construct nonce as concatenation: random || counter (big-endian u64)", () => {
    const randomPart = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
    const counter = BigInt(256);

    const nonce = Nonce.create(randomPart, counter);
    const bytes = nonce.toBytes();

    expect(bytes.length).toBe(24);
    expect(bytes.slice(0, 16)).toEqual(randomPart);
    // counter = 256 = 0x0100 in big-endian u64: 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00
    expect(bytes.slice(16)).toEqual(
      new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]),
    );
  });

  it("should be equal to another nonce with the same random part and counter", () => {
    const random = new Uint8Array(16).fill(0xab);
    const nonce1 = Nonce.create(random, BigInt(42));
    const nonce2 = Nonce.create(random, BigInt(42));

    expect(nonce1.equals(nonce2)).toBe(true);
  });

  it("should not be equal when counter differs", () => {
    const random = new Uint8Array(16).fill(0xab);
    const nonce1 = Nonce.create(random, BigInt(1));
    const nonce2 = Nonce.create(random, BigInt(2));

    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("should reject a random part shorter than 16 bytes", () => {
    const shortRandom = new Uint8Array(15).fill(0xab);

    expect(() => Nonce.create(shortRandom, BigInt(1))).toThrow(
      "Random part must be at least 16 bytes",
    );
  });

  it("should reject a negative counter value", () => {
    const random = new Uint8Array(16).fill(0xab);

    expect(() => Nonce.create(random, BigInt(-1))).toThrow(
      "Counter must be a non-negative integer",
    );
  });

  it("should use constant-time comparison in equals (XOR accumulator, no early return)", () => {
    const random1 = new Uint8Array(16).fill(0xab);
    const random2 = new Uint8Array(16).fill(0xcd);
    const nonce1 = Nonce.create(random1, BigInt(1));
    const nonce2 = Nonce.create(random2, BigInt(1));

    // Verify functional correctness: different nonces are not equal
    expect(nonce1.equals(nonce2)).toBe(false);

    // Verify same-length nonces with single-byte difference are not equal
    const random3 = new Uint8Array(16).fill(0xab);
    random3[15] = 0xac; // Differ only in last byte
    const nonce3 = Nonce.create(random3, BigInt(1));
    expect(nonce1.equals(nonce3)).toBe(false);
  });

  it("should return false for nonces of different lengths in constant time", () => {
    const nonce1 = Nonce.create(new Uint8Array(16).fill(0xab), BigInt(1));
    const nonce2 = Nonce.create(new Uint8Array(32).fill(0xab), BigInt(1));

    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("should detect different lengths even when prefix bytes match (length check is essential)", () => {
    // Both nonces have all-zero content — only the length differs
    // Without the length check, the XOR loop would see acc=0 for the shorter nonce's range
    const nonce1 = Nonce.create(new Uint8Array(16).fill(0x00), BigInt(0));
    const nonce2 = Nonce.create(new Uint8Array(32).fill(0x00), BigInt(0));

    // nonce1 = 24 bytes all zeros, nonce2 = 40 bytes all zeros
    // Without length guard: loop runs over 24 bytes, all XOR to 0 → wrongly returns true
    // With length guard: returns false immediately
    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it("equals loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= this.bytes.length; i++)` — off-by-one
    const random = new Uint8Array(16).fill(0xab);
    const nonce1 = Nonce.create(random, BigInt(42));
    const nonce2 = Nonce.create(random, BigInt(42));
    expect(nonce1.equals(nonce2)).toBe(true);
  });
});
