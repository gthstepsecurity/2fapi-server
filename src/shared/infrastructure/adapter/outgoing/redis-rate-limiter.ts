// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Redis-backed sliding window rate limiter.
 *
 * Implements the rate limiter port used by multiple bounded contexts
 * (authentication-challenge, client-registration, zk-verification).
 *
 * Uses a Redis sorted set per client with timestamps as scores.
 * The sliding window approach counts requests within the last `windowMs`
 * milliseconds and rejects if the count exceeds `maxRequests`.
 *
 * This is a SHARED infrastructure adapter — each bounded context
 * wires it independently with its own key prefix and configuration.
 */

/**
 * Minimal Redis client interface for rate limiting operations.
 */
export interface RedisClient {
  multi(): RedisMulti;
}

/**
 * Redis multi/pipeline interface for atomic operations.
 */
export interface RedisMulti {
  zremrangebyscore(key: string, min: string | number, max: string | number): RedisMulti;
  zadd(key: string, ...args: (string | number)[]): RedisMulti;
  zcard(key: string): RedisMulti;
  expire(key: string, seconds: number): RedisMulti;
  exec(): Promise<unknown[]>;
}

/**
 * Configuration for the sliding window rate limiter.
 */
export interface RateLimiterConfig {
  /** Maximum number of requests allowed within the window. */
  readonly maxRequests: number;
  /** Window duration in milliseconds. */
  readonly windowMs: number;
  /** Key prefix for Redis keys (e.g., "ratelimit:auth:"). */
  readonly keyPrefix: string;
}

/**
 * Rate limiter interface matching the domain port shape.
 * This avoids importing from a specific bounded context.
 */
export interface RateLimiterPort {
  isAllowed(clientIdentifier: string): Promise<boolean>;
}

/**
 * Redis sliding window rate limiter.
 *
 * Algorithm:
 * 1. Remove all entries older than (now - windowMs) from the sorted set
 * 2. Add the current request with score = now
 * 3. Count remaining entries
 * 4. If count <= maxRequests, allow; otherwise deny
 * 5. Set TTL on the key to auto-cleanup
 *
 * All operations are atomic via MULTI/EXEC.
 */
export class RedisRateLimiter implements RateLimiterPort {
  constructor(
    private readonly redis: RedisClient,
    private readonly config: RateLimiterConfig,
    private readonly clock: { nowMs(): number } = { nowMs: () => Date.now() },
  ) {}

  async isAllowed(clientIdentifier: string): Promise<boolean> {
    const key = this.config.keyPrefix + clientIdentifier;
    const nowMs = this.clock.nowMs();
    const windowStartMs = nowMs - this.config.windowMs;
    const ttlSeconds = Math.ceil(this.config.windowMs / 1000);

    const results = await this.redis
      .multi()
      .zremrangebyscore(key, "-inf", windowStartMs)
      .zadd(key, nowMs, `${nowMs}:${Math.random().toString(36).slice(2)}`)
      .zcard(key)
      .expire(key, ttlSeconds)
      .exec();

    // results[2] is the ZCARD result (count of entries in window)
    const count = results[2] as number;
    return count <= this.config.maxRequests;
  }
}
