// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RngHealthChecker } from "../../src/shared/rng-health-checker.js";

describe("C-02: RNG health threshold raised to 16 distinct bytes", () => {
  const checker = new RngHealthChecker();

  it("accepts bytes with exactly 16 distinct values", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = i % 16; // 16 distinct values: 0x00..0x0f
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(true);
  });

  it("rejects bytes with only 15 distinct values", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = (i % 15) + 1; // 15 distinct values: 0x01..0x0f
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("rejects bytes with only 4 distinct values (old threshold)", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = [0x01, 0x02, 0x03, 0x04][i % 4]!;
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(false);
    expect(result.error).toBe("rng_low_entropy");
  });

  it("accepts bytes with 32 distinct values", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = i;
    }
    const result = checker.validate(bytes);
    expect(result.healthy).toBe(true);
  });
});
