// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";

describe("LockoutConfig", () => {
  it("creates with default threshold 3 and duration 60 minutes", () => {
    const config = LockoutConfig.defaults();
    expect(config.threshold).toBe(3);
    expect(config.durationMs).toBe(60 * 60 * 1000);
  });

  it("creates with custom threshold and duration", () => {
    const config = LockoutConfig.create(5, 30 * 60 * 1000);
    expect(config.threshold).toBe(5);
    expect(config.durationMs).toBe(30 * 60 * 1000);
  });

  it("rejects threshold less than 1", () => {
    expect(() => LockoutConfig.create(0, 60000)).toThrow("Threshold must be at least 1");
  });

  it("rejects non-integer threshold", () => {
    expect(() => LockoutConfig.create(2.5, 60000)).toThrow("Threshold must be a positive integer");
  });

  it("rejects duration less than or equal to 0", () => {
    expect(() => LockoutConfig.create(3, 0)).toThrow("Duration must be positive");
  });

  it("accepts threshold of exactly 1 (boundary: < 1 not <= 1)", () => {
    // Kill mutant: `if (threshold <= 1)` instead of `< 1`
    const config = LockoutConfig.create(1, 60000);
    expect(config.threshold).toBe(1);
  });

  it("creates with backoff multiplier and max duration", () => {
    const config = LockoutConfig.create(3, 60 * 60 * 1000, 2, 24 * 60 * 60 * 1000);
    expect(config.backoffMultiplier).toBe(2);
    expect(config.maxDurationMs).toBe(24 * 60 * 60 * 1000);
  });

  it("defaults backoff multiplier to 1 and max duration to base duration", () => {
    const config = LockoutConfig.defaults();
    expect(config.backoffMultiplier).toBe(1);
    expect(config.maxDurationMs).toBe(60 * 60 * 1000);
  });

  it("rejects backoff multiplier less than 1", () => {
    expect(() => LockoutConfig.create(3, 60000, 0)).toThrow("Backoff multiplier must be at least 1");
  });

  it("rejects max duration less than or equal to 0", () => {
    expect(() => LockoutConfig.create(3, 60000, 2, 0)).toThrow("Max duration must be positive");
  });
});
