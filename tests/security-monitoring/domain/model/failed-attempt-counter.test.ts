// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";

describe("FailedAttemptCounter", () => {
  const config = LockoutConfig.defaults(); // threshold=3, duration=60min

  it("creates with zero consecutive failures", () => {
    const counter = FailedAttemptCounter.create("alice");
    expect(counter.clientIdentifier).toBe("alice");
    expect(counter.consecutiveFailures).toBe(0);
    expect(counter.lockedOutAtMs).toBeNull();
  });

  it("increments from 0 to 1", () => {
    const counter = FailedAttemptCounter.create("alice");
    const incremented = counter.increment(1700000000000, config);
    expect(incremented.consecutiveFailures).toBe(1);
    expect(incremented.lockedOutAtMs).toBeNull();
  });

  it("increments from 1 to 2", () => {
    const counter = FailedAttemptCounter.create("alice").increment(1000, config);
    const incremented = counter.increment(2000, config);
    expect(incremented.consecutiveFailures).toBe(2);
    expect(incremented.lockedOutAtMs).toBeNull();
  });

  it("increments from 2 to 3 and triggers lockout", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    const locked = counter.increment(3000, config);
    expect(locked.consecutiveFailures).toBe(3);
    expect(locked.lockedOutAtMs).toBe(3000);
  });

  it("decrements by 1 on success instead of resetting to 0 (BE08)", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    // 2 failures, then success → 1 failure (not 0)
    const afterSuccess = counter.recordSuccess();
    expect(afterSuccess.consecutiveFailures).toBe(1);
    expect(afterSuccess.lockedOutAtMs).toBeNull();
  });

  it("success cannot bring counter below 0 (BE08)", () => {
    const counter = FailedAttemptCounter.create("alice");
    const afterSuccess = counter.recordSuccess();
    expect(afterSuccess.consecutiveFailures).toBe(0);
  });

  it("lockout evasion via alternation is prevented (BE08)", () => {
    // Attacker tries: 2 failures → 1 success → 2 failures → should lock out
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config); // 1
    counter = counter.increment(2000, config); // 2
    counter = counter.recordSuccess(); // 1 (not 0)
    counter = counter.increment(3000, config); // 2
    counter = counter.increment(4000, config); // 3 → lockout!
    expect(counter.consecutiveFailures).toBe(3);
    expect(counter.isLockedOut(4000, config)).toBe(true);
  });

  it("resets to 0 on success (legacy reset method)", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    const reset = counter.reset();
    expect(reset.consecutiveFailures).toBe(0);
    expect(reset.lockedOutAtMs).toBeNull();
  });

  it("is not locked out at 2 failures", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    expect(counter.isLockedOut(2500, config)).toBe(false);
  });

  it("is locked out at 3 failures within duration", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(counter.isLockedOut(3000, config)).toBe(true);
  });

  it("lockout expires after duration", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    const afterDuration = 3000 + config.durationMs + 1;
    expect(counter.isLockedOut(afterDuration, config)).toBe(false);
  });

  it("counter stays at 3 after lockout expiry (not reset until success)", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    const afterExpiry = 3000 + config.durationMs + 1;
    expect(counter.isLockedOut(afterExpiry, config)).toBe(false);
    expect(counter.consecutiveFailures).toBe(3);
  });

  it("is locked out with custom config (threshold=5)", () => {
    const customConfig = LockoutConfig.create(5, 60000);
    let counter = FailedAttemptCounter.create("alice");
    for (let i = 0; i < 4; i++) {
      counter = counter.increment(i * 1000, customConfig);
    }
    expect(counter.isLockedOut(5000, customConfig)).toBe(false);
    counter = counter.increment(5000, customConfig);
    expect(counter.consecutiveFailures).toBe(5);
    expect(counter.isLockedOut(5000, customConfig)).toBe(true);
  });

  it("restores from existing state", () => {
    const counter = FailedAttemptCounter.restore("alice", 2, null);
    expect(counter.clientIdentifier).toBe("alice");
    expect(counter.consecutiveFailures).toBe(2);
    expect(counter.lockedOutAtMs).toBeNull();
  });

  it("restores from locked state", () => {
    const counter = FailedAttemptCounter.restore("alice", 3, 5000);
    expect(counter.isLockedOut(5000, config)).toBe(true);
  });

  it("is locked out at exactly the end of duration (inclusive boundary)", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    // lockedOutAtMs = 3000, durationMs = 3600000
    // boundary = 3000 + 3600000 = 3603000
    expect(counter.isLockedOut(3603000, config)).toBe(true);
    expect(counter.isLockedOut(3603001, config)).toBe(false);
  });

  it("refreshes lockedOutAtMs on each increment above threshold (extends lockout)", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(counter.lockedOutAtMs).toBe(3000);
    // 4th increment while still locked updates the lockout timestamp (extends lockout)
    const incremented = counter.increment(4000, config);
    expect(incremented.consecutiveFailures).toBe(4);
    expect(incremented.lockedOutAtMs).toBe(4000); // refreshed to prevent bypass
  });

  it("reset clears both failures and lockout timestamp", () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(counter.lockedOutAtMs).toBe(3000);
    const reset = counter.reset();
    expect(reset.consecutiveFailures).toBe(0);
    expect(reset.lockedOutAtMs).toBeNull();
    expect(reset.clientIdentifier).toBe("alice");
  });

  it("isLockedOut returns false when lockedOutAtMs is null even with high failures", () => {
    // Edge case: restore with 5 failures but no lockout timestamp
    const counter = FailedAttemptCounter.restore("alice", 5, null);
    expect(counter.isLockedOut(1000, config)).toBe(false);
  });

  it("isLockedOut returns false when below threshold (block statement guard)", () => {
    // Kill mutant: `if (this.consecutiveFailures < config.threshold) {}` (empty block)
    // and: `if (false)` instead of the threshold check
    // With 2 failures (below threshold of 3), should return false
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    expect(counter.consecutiveFailures).toBe(2);
    // This should return false because 2 < 3 (threshold)
    expect(counter.isLockedOut(2500, config)).toBe(false);
    // With the mutant (empty block or `if (false)`), the method would
    // fall through to check lockedOutAtMs, which is null → false anyway
    // BUT we need to verify that explicitly restoring with high count and null lockout
    // still works correctly
    const restoredHigh = FailedAttemptCounter.restore("bob", 5, null);
    expect(restoredHigh.isLockedOut(1000, config)).toBe(false);
  });

  it("isLockedOut correctly returns false when below threshold even with lockout timestamp", () => {
    // Kill mutant: `if (this.consecutiveFailures < config.threshold) { return false; }`
    // → `if (this.consecutiveFailures < config.threshold) {}` (empty block)
    // If block is empty, method continues and checks lockedOutAtMs which would be non-null
    // This would wrongly return true for below-threshold with lockout timestamp
    const counter = FailedAttemptCounter.restore("alice", 1, 5000);
    // 1 failure < 3 threshold, should return false regardless of lockout timestamp
    expect(counter.isLockedOut(5000, config)).toBe(false);
  });

  it("re-locks out after first lockout expires and new failures reach threshold", () => {
    // First lockout cycle: 3 failures → locked at 3000
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(counter.isLockedOut(3000, config)).toBe(true);
    expect(counter.lockedOutAtMs).toBe(3000);

    // Lockout expires
    const afterExpiry = 3000 + config.durationMs + 1;
    expect(counter.isLockedOut(afterExpiry, config)).toBe(false);

    // New failure after expiry — should trigger new lockout with updated timestamp
    const reLocked = counter.increment(afterExpiry + 100, config);
    expect(reLocked.consecutiveFailures).toBe(4);
    // The lockout timestamp must be updated to the NEW time, not the old one
    expect(reLocked.lockedOutAtMs).toBe(afterExpiry + 100);
    expect(reLocked.isLockedOut(afterExpiry + 100, config)).toBe(true);
  });

  it("first lockout uses base duration with backoff config", () => {
    const backoffConfig = LockoutConfig.create(3, 60 * 60 * 1000, 2, 24 * 60 * 60 * 1000);
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, backoffConfig);
    counter = counter.increment(2000, backoffConfig);
    counter = counter.increment(3000, backoffConfig);
    // First lockout: duration = 60min * 2^0 = 60min
    expect(counter.isLockedOut(3000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(3000 + 60 * 60 * 1000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(3000 + 60 * 60 * 1000 + 1, backoffConfig)).toBe(false);
  });

  it("second lockout doubles duration with multiplier=2", () => {
    const backoffConfig = LockoutConfig.create(3, 60 * 60 * 1000, 2, 24 * 60 * 60 * 1000);
    let counter = FailedAttemptCounter.create("alice");
    // First lockout
    counter = counter.increment(1000, backoffConfig);
    counter = counter.increment(2000, backoffConfig);
    counter = counter.increment(3000, backoffConfig);
    expect(counter.lockoutCount).toBe(1);

    // Reset and second lockout
    counter = counter.reset();
    counter = counter.increment(100000, backoffConfig);
    counter = counter.increment(200000, backoffConfig);
    counter = counter.increment(300000, backoffConfig);
    expect(counter.lockoutCount).toBe(2);
    // Second lockout: duration = 60min * 2^1 = 120min
    expect(counter.isLockedOut(300000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(300000 + 120 * 60 * 1000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(300000 + 120 * 60 * 1000 + 1, backoffConfig)).toBe(false);
  });

  it("lockout duration capped at max duration", () => {
    const backoffConfig = LockoutConfig.create(3, 60 * 60 * 1000, 2, 24 * 60 * 60 * 1000);
    // Simulate 10 lockouts via restore
    let counter = FailedAttemptCounter.restore("alice", 0, null, 10);
    counter = counter.increment(1000, backoffConfig);
    counter = counter.increment(2000, backoffConfig);
    counter = counter.increment(3000, backoffConfig);
    // Duration would be 60min * 2^10 = huge, but capped at 24h
    expect(counter.isLockedOut(3000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(3000 + 24 * 60 * 60 * 1000, backoffConfig)).toBe(true);
    expect(counter.isLockedOut(3000 + 24 * 60 * 60 * 1000 + 1, backoffConfig)).toBe(false);
  });

  it("backoff multiplier of 1 gives constant duration", () => {
    const noBackoff = LockoutConfig.create(3, 60 * 60 * 1000, 1, 24 * 60 * 60 * 1000);
    let counter = FailedAttemptCounter.restore("alice", 0, null, 5);
    counter = counter.increment(1000, noBackoff);
    counter = counter.increment(2000, noBackoff);
    counter = counter.increment(3000, noBackoff);
    // Duration = 60min * 1^5 = 60min (constant)
    expect(counter.isLockedOut(3000 + 60 * 60 * 1000, noBackoff)).toBe(true);
    expect(counter.isLockedOut(3000 + 60 * 60 * 1000 + 1, noBackoff)).toBe(false);
  });

  it("reset preserves lockout count for backoff escalation", () => {
    const backoffConfig = LockoutConfig.create(3, 60 * 60 * 1000, 2, 24 * 60 * 60 * 1000);
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, backoffConfig);
    counter = counter.increment(2000, backoffConfig);
    counter = counter.increment(3000, backoffConfig);
    expect(counter.lockoutCount).toBe(1);
    const reset = counter.reset();
    // lockoutCount persists across resets so backoff escalates
    expect(reset.lockoutCount).toBe(1);
    expect(reset.consecutiveFailures).toBe(0);
    expect(reset.lockedOutAtMs).toBeNull();
  });

  it("updates lockout timestamp on each subsequent threshold breach", () => {
    // Reach threshold at time 3000 → locked
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    expect(counter.lockedOutAtMs).toBe(3000);

    // Wait for lockout to expire, then fail again at new time
    const expiry1 = 3000 + config.durationMs + 1;
    counter = counter.increment(expiry1, config);
    // Now at 4 failures, still above threshold, lockout timestamp must refresh
    expect(counter.lockedOutAtMs).toBe(expiry1);
    // Must be locked out again from the new timestamp
    expect(counter.isLockedOut(expiry1, config)).toBe(true);

    // And this new lockout also expires correctly
    const expiry2 = expiry1 + config.durationMs + 1;
    expect(counter.isLockedOut(expiry2, config)).toBe(false);
  });
});
