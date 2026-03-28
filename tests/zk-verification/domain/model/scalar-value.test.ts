// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ScalarValue } from "../../../../src/zk-verification/domain/model/scalar-value.js";

describe("ScalarValue", () => {
  const SCALAR_BYTE_LENGTH = 32;

  it("should be created from exactly 32 bytes", () => {
    const bytes = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0x01);
    const scalar = ScalarValue.fromBytes(bytes);
    expect(scalar.toBytes()).toEqual(bytes);
  });

  it("should reject bytes not exactly 32 bytes long", () => {
    expect(() => ScalarValue.fromBytes(new Uint8Array(31))).toThrow(
      "Scalar must be exactly 32 bytes",
    );
    expect(() => ScalarValue.fromBytes(new Uint8Array(33))).toThrow(
      "Scalar must be exactly 32 bytes",
    );
  });

  it("should return a defensive copy from toBytes", () => {
    const original = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xaa);
    const scalar = ScalarValue.fromBytes(original);
    const copy = scalar.toBytes();
    copy[0] = 0xff;
    expect(scalar.toBytes()[0]).toBe(0xaa);
  });

  it("should accept the zero scalar (algebraically valid)", () => {
    const zero = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0x00);
    const scalar = ScalarValue.fromBytes(zero);
    expect(scalar.isZero()).toBe(true);
  });

  it("should report non-zero for a non-zero scalar", () => {
    const nonZero = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0x00);
    nonZero[0] = 0x01;
    const scalar = ScalarValue.fromBytes(nonZero);
    expect(scalar.isZero()).toBe(false);
  });

  it("should use constant-time comparison in equals", () => {
    const a = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xab);
    const b = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xab);
    const c = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xcd);

    expect(ScalarValue.fromBytes(a).equals(ScalarValue.fromBytes(b))).toBe(true);
    expect(ScalarValue.fromBytes(a).equals(ScalarValue.fromBytes(c))).toBe(false);
  });

  it("isZero loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= this.bytes.length; i++)` — off-by-one
    const nonZero = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0x00);
    nonZero[31] = 0x01; // only last byte differs
    const scalar = ScalarValue.fromBytes(nonZero);
    expect(scalar.isZero()).toBe(false);
  });

  it("equals loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= SCALAR_BYTE_LENGTH; i++)` — off-by-one
    const a = ScalarValue.fromBytes(new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xab));
    const b = ScalarValue.fromBytes(new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xab));
    expect(a.equals(b)).toBe(true);

    // Verify last-byte difference is detected
    const c = new Uint8Array(SCALAR_BYTE_LENGTH).fill(0xab);
    c[31] = 0xac;
    expect(a.equals(ScalarValue.fromBytes(c))).toBe(false);
  });
});
