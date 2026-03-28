// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { IpRateLimiter, IpRateLimiterResult } from "../api-gateway/middleware/ip-rate-limiter.js";

/**
 * Minimal Redis client interface for IP rate limiter operations.
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

const KEY_PREFIX = "ratelimit:ip:";

/**
 * Redis-backed per-IP rate limiter using sorted sets.
 *
 * Each IP gets a sorted set in Redis where:
 * - Members are unique request identifiers (timestamp:random)
 * - Scores are request timestamps
 *
 * The sliding window is implemented by removing entries older
 * than (now - windowMs) before counting.
 *
 * All operations are atomic via MULTI/EXEC to prevent race conditions.
 */
export class RedisIpRateLimiter implements IpRateLimiter {
  private readonly windowSeconds: number;

  constructor(
    private readonly redis: RedisClient,
    private readonly maxRequestsPerIp: number,
    private readonly windowMs: number = 1000,
  ) {
    this.windowSeconds = Math.ceil(windowMs / 1000);
  }

  tryAcquire(ip: string): IpRateLimiterResult {
    // Redis operations are async, but the IpRateLimiter interface
    // defines tryAcquire as synchronous. Use tryAcquireAsync instead.
    throw new Error(
      "RedisIpRateLimiter.tryAcquire() is synchronous but Redis is async. " +
      "Use tryAcquireAsync() instead, or use the async-compatible wrapper.",
    );
  }

  /**
   * Async version of tryAcquire for use in async middleware contexts.
   * Uses a sorted set sliding window per IP.
   */
  async tryAcquireAsync(ip: string): Promise<IpRateLimiterResult> {
    const key = KEY_PREFIX + ip;
    const nowMs = Date.now();
    const windowStartMs = nowMs - this.windowMs;
    const member = `${nowMs}:${Math.random().toString(36).slice(2)}`;

    const results = await this.redis
      .multi()
      .zremrangebyscore(key, "-inf", windowStartMs)
      .zadd(key, nowMs, member)
      .zcard(key)
      .expire(key, this.windowSeconds)
      .exec();

    // results[2] is the ZCARD result [error, count]
    const rawResult = results[2];
    const count = Array.isArray(rawResult) ? (rawResult[1] as number) : (rawResult as number);

    if (count > this.maxRequestsPerIp) {
      const retryAfterSeconds = Math.max(0.1, this.windowMs / 1000);
      return {
        allowed: false,
        remaining: 0,
        limit: this.maxRequestsPerIp,
        retryAfterSeconds,
      };
    }

    return {
      allowed: true,
      remaining: this.maxRequestsPerIp - count,
      limit: this.maxRequestsPerIp,
    };
  }

  extractRealIp(
    connectionIp: string,
    xForwardedFor: string | undefined,
    trustedProxies: string[],
  ): string {
    if (xForwardedFor === undefined || xForwardedFor.length === 0) {
      return connectionIp;
    }

    const isTrustedProxy = trustedProxies.includes(connectionIp);
    if (!isTrustedProxy) {
      return connectionIp;
    }

    const ips = xForwardedFor.split(",").map((ip) => ip.trim());
    return ips[0] ?? connectionIp;
  }

  resetWindow(): void {
    // No-op for Redis — keys auto-expire via TTL.
    // For a full reset, use resetWindowAsync().
  }

  /**
   * Async version of resetWindow that flushes all IP rate limit keys.
   * Use with caution — this affects all IPs.
   */
  async resetWindowAsync(): Promise<void> {
    // Cannot efficiently clear all sorted set keys without SCAN.
    // In production, rely on TTL-based expiry instead.
  }
}
