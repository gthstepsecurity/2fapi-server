// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { LockoutStatus } from "../../../../src/security-monitoring/domain/model/lockout-status.js";

describe("LockoutStatus", () => {
  it("creates an unlocked status", () => {
    const status = LockoutStatus.unlocked();
    expect(status.isLocked).toBe(false);
    expect(status.lockedOutAtMs).toBeNull();
  });

  it("creates a locked status with timestamp", () => {
    const now = 1700000000000;
    const status = LockoutStatus.locked(now);
    expect(status.isLocked).toBe(true);
    expect(status.lockedOutAtMs).toBe(now);
  });

  it("locked status rejects negative timestamp", () => {
    expect(() => LockoutStatus.locked(-1)).toThrow("Lockout timestamp must be non-negative");
  });

  it("locked status accepts exactly 0 timestamp (boundary: < 0 not <= 0)", () => {
    // Kill mutant: `if (lockedOutAtMs <= 0)` instead of `< 0`
    const status = LockoutStatus.locked(0);
    expect(status.isLocked).toBe(true);
    expect(status.lockedOutAtMs).toBe(0);
  });
});
