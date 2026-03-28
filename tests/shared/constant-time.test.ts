// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, vi } from "vitest";
import {
  constantTimeEqual,
  isNativeAvailable,
  setWarnOnFallback,
  resetNativeConstantTimeModule,
  setNativeConstantTimeModule,
} from "../../src/shared/constant-time.js";

describe("constantTimeEqual", () => {
  it("returns true for equal buffers", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("returns false for different buffers", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns false for buffers of different lengths (no early return)", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns true for empty buffers", () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array(0);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("detects single-byte difference at end", () => {
    const a = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    const b = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xff]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("detects single-byte difference at start", () => {
    const a = new Uint8Array([0x01, 0xbb, 0xcc, 0xdd, 0xee]);
    const b = new Uint8Array([0x02, 0xbb, 0xcc, 0xdd, 0xee]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns true for identical 32-byte buffers (typical hash size)", () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      a[i] = i;
      b[i] = i;
    }
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("returns false for 32-byte buffers differing only in last byte", () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      a[i] = i;
      b[i] = i;
    }
    b[31] = 0xff;
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("handles all-zeros vs all-zeros", () => {
    const a = new Uint8Array(16).fill(0);
    const b = new Uint8Array(16).fill(0);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("handles all-ones vs all-zeros", () => {
    const a = new Uint8Array(16).fill(0xff);
    const b = new Uint8Array(16).fill(0x00);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("uses Math.max for iteration length (not Math.min)", () => {
    // Kill mutant: Math.min instead of Math.max
    // With Math.min, comparing [1,2,3] to [1,2,3,4,5] would only check 3 bytes
    // and the XOR loop would wrongly find acc=0 for matching prefix
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 0, 0]);
    // Different lengths → false (due to length XOR in acc)
    expect(constantTimeEqual(a, b)).toBe(false);
    // But also verify that a zero-padded array is detected
    const c = new Uint8Array([1, 2, 3, 0, 0]);
    const d = new Uint8Array([1, 2, 3, 0, 1]);
    expect(constantTimeEqual(c, d)).toBe(false);
  });

  it("uses < (not <=) in loop boundary", () => {
    // Kill mutant: `for (let i = 0; i <= maxLen; i++)` — off-by-one
    // With <=, accessing a[maxLen] or b[maxLen] returns undefined
    // which when XORed could produce NaN, breaking the logic
    const a = new Uint8Array([0xaa, 0xbb]);
    const b = new Uint8Array([0xaa, 0xbb]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });
});

describe("isNativeAvailable", () => {
  it("returns false when no native module is set", () => {
    resetNativeConstantTimeModule();
    expect(isNativeAvailable()).toBe(false);
  });

  it("returns true when native module is injected", () => {
    setNativeConstantTimeModule({
      constantTimeEq: () => true,
    });
    expect(isNativeAvailable()).toBe(true);
    resetNativeConstantTimeModule();
  });
});

describe("warnOnFallback", () => {
  it("emits warning to stderr when fallback is used and warnOnFallback is enabled", () => {
    resetNativeConstantTimeModule();
    setWarnOnFallback(true);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const result = constantTimeEqual(a, b);

    expect(result).toBe(true);
    expect(stderrSpy).toHaveBeenCalledOnce();
    expect(stderrSpy.mock.calls[0]![0]).toContain("[2fapi] WARNING");

    stderrSpy.mockRestore();
    setWarnOnFallback(false);
  });

  it("does not warn when warnOnFallback is disabled", () => {
    resetNativeConstantTimeModule();
    setWarnOnFallback(false);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    constantTimeEqual(new Uint8Array([1]), new Uint8Array([1]));

    expect(stderrSpy).not.toHaveBeenCalled();

    stderrSpy.mockRestore();
  });

  it("warning is emitted only once per process (not on every call)", () => {
    resetNativeConstantTimeModule();
    setWarnOnFallback(true);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    constantTimeEqual(new Uint8Array([1]), new Uint8Array([1]));
    constantTimeEqual(new Uint8Array([2]), new Uint8Array([2]));
    constantTimeEqual(new Uint8Array([3]), new Uint8Array([3]));

    expect(stderrSpy).toHaveBeenCalledOnce();

    stderrSpy.mockRestore();
    setWarnOnFallback(false);
  });
});
