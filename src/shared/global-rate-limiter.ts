// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Global rate limiter interface.
 *
 * Tracks total requests across all clients within a time window.
 * Production implementations should use a shared counter (Redis INCR with TTL)
 * for horizontal scaling. This module provides an in-memory reference
 * implementation.
 */

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly retryAfterSeconds?: number;
}

export interface GlobalRateLimiter {
  tryAcquire(): RateLimitResult;
  currentCount(): number;
  resetWindow(): void;
}

/**
 * In-memory global rate limiter using a sliding window counter.
 *
 * @warning DEVELOPMENT ONLY — This implementation is process-local.
 * In a multi-instance deployment, each process maintains its own counter,
 * effectively multiplying the rate limit by N instances (CC01).
 * For production with horizontal scaling, use a Redis-backed rate limiter
 * (e.g., Redis INCR with TTL) to share state across instances.
 */
export class InMemoryGlobalRateLimiter implements GlobalRateLimiter {
  private count = 0;
  private windowStartMs: number;

  constructor(
    private readonly maxRequestsPerWindow: number,
    private readonly windowMs: number = 1000,
  ) {
    this.windowStartMs = Date.now();
  }

  tryAcquire(): RateLimitResult {
    this.maybeResetWindow();

    if (this.count >= this.maxRequestsPerWindow) {
      const elapsedMs = Date.now() - this.windowStartMs;
      const remainingMs = Math.max(0, this.windowMs - elapsedMs);
      const retryAfterSeconds = Math.max(0.1, remainingMs / 1000);
      return { allowed: false, retryAfterSeconds };
    }

    this.count++;
    return { allowed: true };
  }

  currentCount(): number {
    this.maybeResetWindow();
    return this.count;
  }

  resetWindow(): void {
    this.count = 0;
    this.windowStartMs = Date.now();
  }

  private maybeResetWindow(): void {
    const now = Date.now();
    if (now - this.windowStartMs >= this.windowMs) {
      this.count = 0;
      this.windowStartMs = now;
    }
  }
}
