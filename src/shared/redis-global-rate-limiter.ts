// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { GlobalRateLimiter, RateLimitResult } from "./global-rate-limiter.js";

/**
 * Minimal Redis client interface for global rate limiter operations.
 */
export interface RedisClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  ttl(key: string): Promise<number>;
}

const DEFAULT_KEY = "ratelimit:global";

/**
 * Redis-backed global rate limiter using INCR with TTL.
 *
 * Uses a single Redis key with a counter that auto-expires after
 * the window duration. This provides a fixed-window rate limit
 * that is shared across all application instances.
 *
 * The fixed-window approach is simpler than sliding window and
 * appropriate for global rate limiting where exact precision
 * at window boundaries is not critical.
 */
export class RedisGlobalRateLimiter implements GlobalRateLimiter {
  private readonly key: string;
  private readonly windowSeconds: number;

  constructor(
    private readonly redis: RedisClient,
    private readonly maxRequestsPerWindow: number,
    private readonly windowMs: number = 1000,
    key: string = DEFAULT_KEY,
  ) {
    this.key = key;
    this.windowSeconds = Math.ceil(windowMs / 1000);
  }

  tryAcquire(): RateLimitResult {
    // Redis operations are async, but the GlobalRateLimiter interface
    // defines tryAcquire as synchronous. We use a fire-and-forget
    // increment and track count locally with async pre-fetch.
    // For production, consider using tryAcquireAsync instead.
    throw new Error(
      "RedisGlobalRateLimiter.tryAcquire() is synchronous but Redis is async. " +
      "Use tryAcquireAsync() instead, or use the async-compatible wrapper.",
    );
  }

  /**
   * Async version of tryAcquire for use in async middleware contexts.
   * Atomically increments the counter and checks against the limit.
   */
  async tryAcquireAsync(): Promise<RateLimitResult> {
    const count = await this.redis.incr(this.key);

    // Set expiry on first request of the window
    if (count === 1) {
      await this.redis.expire(this.key, this.windowSeconds);
    }

    if (count > this.maxRequestsPerWindow) {
      const ttl = await this.redis.ttl(this.key);
      const retryAfterSeconds = ttl > 0 ? ttl : Math.max(0.1, this.windowMs / 1000);
      return { allowed: false, retryAfterSeconds };
    }

    return { allowed: true };
  }

  currentCount(): number {
    // Synchronous interface limitation — return 0 as a fallback.
    // Production code should use currentCountAsync().
    return 0;
  }

  /**
   * Async version of currentCount.
   */
  async currentCountAsync(): Promise<number> {
    const raw = await this.redis.get(this.key);
    return raw !== null ? parseInt(raw, 10) : 0;
  }

  resetWindow(): void {
    // Fire-and-forget delete for synchronous interface.
    void this.redis.del(this.key);
  }

  /**
   * Async version of resetWindow.
   */
  async resetWindowAsync(): Promise<void> {
    await this.redis.del(this.key);
  }
}
