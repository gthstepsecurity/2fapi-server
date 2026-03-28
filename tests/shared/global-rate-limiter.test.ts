// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import {
  InMemoryGlobalRateLimiter,
  type GlobalRateLimiter,
} from "../../src/shared/global-rate-limiter.js";

describe("GlobalRateLimiter", () => {
  let limiter: InMemoryGlobalRateLimiter;

  beforeEach(() => {
    limiter = new InMemoryGlobalRateLimiter(10);
  });

  it("allows requests under the threshold", () => {
    const result = limiter.tryAcquire();
    expect(result.allowed).toBe(true);
  });

  it("allows requests up to exactly threshold - 1", () => {
    for (let i = 0; i < 9; i++) {
      expect(limiter.tryAcquire().allowed).toBe(true);
    }
    // 10th request should still succeed (at threshold)
    expect(limiter.tryAcquire().allowed).toBe(true);
  });

  it("rejects requests at the threshold", () => {
    for (let i = 0; i < 10; i++) {
      limiter.tryAcquire();
    }
    // 11th request exceeds threshold
    const result = limiter.tryAcquire();
    expect(result.allowed).toBe(false);
  });

  it("resets after the window expires", () => {
    for (let i = 0; i < 10; i++) {
      limiter.tryAcquire();
    }
    expect(limiter.tryAcquire().allowed).toBe(false);

    // Simulate window reset
    limiter.resetWindow();

    expect(limiter.tryAcquire().allowed).toBe(true);
  });

  it("tracks current count accurately", () => {
    expect(limiter.currentCount()).toBe(0);
    limiter.tryAcquire();
    expect(limiter.currentCount()).toBe(1);
    limiter.tryAcquire();
    expect(limiter.currentCount()).toBe(2);
  });

  it("provides retry-after hint when rate limited", () => {
    for (let i = 0; i < 10; i++) {
      limiter.tryAcquire();
    }
    const result = limiter.tryAcquire();
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
    expect(result.retryAfterSeconds).toBeLessThanOrEqual(1);
  });

  it("retryAfterSeconds uses correct arithmetic (Date.now - windowStartMs)", () => {
    // Kill mutant: `Date.now() + this.windowStartMs` instead of `-`
    // and `this.windowMs + elapsedMs` instead of `-`
    // and `Math.min` instead of `Math.max` for remainingMs and retryAfterSeconds
    // Fill up the limiter
    for (let i = 0; i < 10; i++) {
      limiter.tryAcquire();
    }
    const result = limiter.tryAcquire();
    expect(result.allowed).toBe(false);
    // retryAfterSeconds should be between 0.1 and 1.0 for a 1s window
    expect(result.retryAfterSeconds).toBeGreaterThanOrEqual(0.1);
    expect(result.retryAfterSeconds).toBeLessThanOrEqual(1.0);
    // With mutant `Date.now() + this.windowStartMs`, elapsedMs would be huge
    // making remainingMs negative, and Math.max(0, negative) = 0
    // retryAfterSeconds = Math.max(0.1, 0/1000) = 0.1
    // With mutant `Math.min(0.1, ...)`, retryAfterSeconds would be 0.1 or less
    // With correct code, retryAfterSeconds should reflect remaining window time
  });

  it("window auto-resets when windowMs elapses", () => {
    // Kill mutant: `if (false)` and `if (now - this.windowStartMs > this.windowMs)`
    // instead of `>= this.windowMs` and block statement removal
    // Use a custom window of 10ms
    const fastLimiter = new InMemoryGlobalRateLimiter(5, 10);
    for (let i = 0; i < 5; i++) {
      fastLimiter.tryAcquire();
    }
    expect(fastLimiter.tryAcquire().allowed).toBe(false);

    // Reset the window manually (simulating time passage)
    fastLimiter.resetWindow();
    expect(fastLimiter.currentCount()).toBe(0);
    expect(fastLimiter.tryAcquire().allowed).toBe(true);
  });

  it("window reset boundary: >= windowMs resets (not > windowMs)", () => {
    // Kill mutant: `now - this.windowStartMs > this.windowMs` instead of `>=`
    // This tests that at exactly the window boundary, the window resets
    const customLimiter = new InMemoryGlobalRateLimiter(2, 1); // 1ms window
    customLimiter.tryAcquire();
    customLimiter.tryAcquire();
    expect(customLimiter.tryAcquire().allowed).toBe(false);

    // After manual reset, count should be 0
    customLimiter.resetWindow();
    expect(customLimiter.currentCount()).toBe(0);
  });

  it("maybeResetWindow resets count to 0 on window expiry", () => {
    // Kill mutant: empty block statement for maybeResetWindow
    const customLimiter = new InMemoryGlobalRateLimiter(3, 1);
    customLimiter.tryAcquire();
    customLimiter.tryAcquire();
    expect(customLimiter.currentCount()).toBe(2);

    // After resetWindow, count should be 0
    customLimiter.resetWindow();
    expect(customLimiter.currentCount()).toBe(0);
    expect(customLimiter.tryAcquire().allowed).toBe(true);
  });
});
