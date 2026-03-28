// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { LockoutPolicy } from "../../../../src/security-monitoring/domain/service/lockout-policy.js";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";

describe("LockoutPolicy", () => {
  const config = LockoutConfig.defaults();
  const policy = new LockoutPolicy(config);

  it("determines client is not locked at 0 failures", () => {
    const counter = FailedAttemptCounter.create("alice");
    expect(policy.isLockedOut(counter, 1000)).toBe(false);
  });

  it("determines client is not locked at 2 failures", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    expect(policy.isLockedOut(counter, 2500)).toBe(false);
  });

  it("determines client is locked at 3 failures", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(policy.isLockedOut(counter, 3000)).toBe(true);
  });

  it("determines lockout has expired", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    const afterExpiry = 3000 + config.durationMs + 1;
    expect(policy.isLockedOut(counter, afterExpiry)).toBe(false);
  });

  it("detects threshold reached after increment", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    expect(policy.shouldLockOut(counter)).toBe(false);
    counter = counter.increment(3000, config);
    expect(policy.shouldLockOut(counter)).toBe(true);
  });

  it("uses custom config", () => {
    const customConfig = LockoutConfig.create(5, 30 * 60 * 1000);
    const customPolicy = new LockoutPolicy(customConfig);
    let counter = FailedAttemptCounter.create("alice");
    for (let i = 0; i < 4; i++) {
      counter = counter.increment(i * 1000, customConfig);
    }
    expect(customPolicy.shouldLockOut(counter)).toBe(false);
    counter = counter.increment(5000, customConfig);
    expect(customPolicy.shouldLockOut(counter)).toBe(true);
  });
});
