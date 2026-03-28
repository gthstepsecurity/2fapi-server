// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Per-IP rate limiter for the API gateway.
 *
 * Tracks request counts per source IP within a time window.
 * Returns rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining)
 * and Retry-After when the limit is exceeded.
 *
 * IP extraction:
 * - Uses the connection source IP by default
 * - Only trusts X-Forwarded-For from explicitly configured trusted proxies
 * - This prevents IP spoofing attacks via header injection
 */

export interface IpRateLimiterResult {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly limit: number;
  readonly retryAfterSeconds?: number;
}

export interface IpRateLimiter {
  tryAcquire(ip: string): IpRateLimiterResult;
  extractRealIp(
    connectionIp: string,
    xForwardedFor: string | undefined,
    trustedProxies: string[],
  ): string;
  resetWindow(): void;
}

/**
 * In-memory per-IP rate limiter.
 *
 * @warning DEVELOPMENT ONLY — This implementation is process-local.
 * In a multi-instance deployment, each process maintains its own counters,
 * effectively multiplying the per-IP rate limit by N instances (CC02).
 * For production with horizontal scaling, use a Redis-backed rate limiter
 * (e.g., Redis INCR with TTL) to share state across instances.
 */
export class InMemoryIpRateLimiter implements IpRateLimiter {
  private readonly counters = new Map<string, number>();
  private windowStartMs: number;

  constructor(
    private readonly maxRequestsPerIp: number,
    private readonly windowMs: number = 1000,
    private readonly maxEntries: number = 10_000,
  ) {
    this.windowStartMs = Date.now();
  }

  tryAcquire(ip: string): IpRateLimiterResult {
    this.maybeResetWindow();

    // Fail-closed: reject new IPs when the map is at capacity
    if (!this.counters.has(ip) && this.counters.size >= this.maxEntries) {
      const elapsedMs = Date.now() - this.windowStartMs;
      const remainingMs = Math.max(0, this.windowMs - elapsedMs);
      const retryAfterSeconds = Math.max(0.1, remainingMs / 1000);
      return {
        allowed: false,
        remaining: 0,
        limit: this.maxRequestsPerIp,
        retryAfterSeconds,
      };
    }

    const current = this.counters.get(ip) ?? 0;

    if (current >= this.maxRequestsPerIp) {
      const elapsedMs = Date.now() - this.windowStartMs;
      const remainingMs = Math.max(0, this.windowMs - elapsedMs);
      const retryAfterSeconds = Math.max(0.1, remainingMs / 1000);
      return {
        allowed: false,
        remaining: 0,
        limit: this.maxRequestsPerIp,
        retryAfterSeconds,
      };
    }

    const newCount = current + 1;
    this.counters.set(ip, newCount);

    return {
      allowed: true,
      remaining: this.maxRequestsPerIp - newCount,
      limit: this.maxRequestsPerIp,
    };
  }

  /**
   * Extracts the real client IP, with protection against X-Forwarded-For spoofing.
   *
   * Only trusts X-Forwarded-For if the connection IP is in the trusted proxy list.
   * When trusted, returns the leftmost (client) IP from the header chain.
   * Otherwise, returns the connection source IP directly.
   */
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

    // Trusted proxy: extract leftmost (original client) IP
    const ips = xForwardedFor.split(",").map((ip) => ip.trim());
    return ips[0] ?? connectionIp;
  }

  resetWindow(): void {
    this.counters.clear();
    this.windowStartMs = Date.now();
  }

  private maybeResetWindow(): void {
    const now = Date.now();
    if (now - this.windowStartMs >= this.windowMs) {
      this.counters.clear();
      this.windowStartMs = now;
    }
  }
}
