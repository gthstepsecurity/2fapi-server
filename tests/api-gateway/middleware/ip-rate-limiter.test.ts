// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import {
  InMemoryIpRateLimiter,
  type IpRateLimiterResult,
} from "../../../src/api-gateway/middleware/ip-rate-limiter.js";

describe("IpRateLimiter", () => {
  let limiter: InMemoryIpRateLimiter;

  beforeEach(() => {
    limiter = new InMemoryIpRateLimiter(5);
  });

  it("allows requests under the per-IP threshold", () => {
    const result = limiter.tryAcquire("10.0.0.1");
    expect(result.allowed).toBe(true);
  });

  it("rejects requests at the per-IP threshold", () => {
    for (let i = 0; i < 5; i++) {
      limiter.tryAcquire("10.0.0.99");
    }
    const result = limiter.tryAcquire("10.0.0.99");
    expect(result.allowed).toBe(false);
  });

  it("tracks different IPs independently", () => {
    for (let i = 0; i < 5; i++) {
      limiter.tryAcquire("10.0.0.1");
    }
    // IP .1 is at limit
    expect(limiter.tryAcquire("10.0.0.1").allowed).toBe(false);

    // IP .2 is fresh — should be allowed
    expect(limiter.tryAcquire("10.0.0.2").allowed).toBe(true);
  });

  it("provides Retry-After seconds on 429", () => {
    for (let i = 0; i < 5; i++) {
      limiter.tryAcquire("10.0.0.50");
    }
    const result = limiter.tryAcquire("10.0.0.50");
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
    expect(result.retryAfterSeconds).toBeLessThanOrEqual(1);
  });

  it("provides remaining count", () => {
    const result = limiter.tryAcquire("10.0.0.1");
    expect(result.remaining).toBe(4); // 5 - 1 = 4
  });

  it("provides rate limit headers when approaching threshold (80%+)", () => {
    // 5 threshold, 80% = 4 requests
    for (let i = 0; i < 3; i++) {
      limiter.tryAcquire("10.0.0.1");
    }
    // 4th request = 80% of limit
    const result = limiter.tryAcquire("10.0.0.1");
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(1);
    expect(result.limit).toBe(5);
  });

  it("extracts real IP from connection, ignoring spoofed X-Forwarded-For", () => {
    const realIp = limiter.extractRealIp(
      "1.2.3.4", // connection source IP
      "10.10.10.10, 192.168.0.1", // spoofed X-Forwarded-For
      [], // no trusted proxies
    );
    expect(realIp).toBe("1.2.3.4");
  });

  it("uses X-Forwarded-For only when proxy is trusted", () => {
    const realIp = limiter.extractRealIp(
      "192.168.1.1", // proxy IP
      "203.0.113.50, 192.168.1.1", // X-Forwarded-For chain
      ["192.168.1.1"], // trusted proxy
    );
    expect(realIp).toBe("203.0.113.50");
  });

  it("resets window for all IPs", () => {
    for (let i = 0; i < 5; i++) {
      limiter.tryAcquire("10.0.0.1");
    }
    expect(limiter.tryAcquire("10.0.0.1").allowed).toBe(false);

    limiter.resetWindow();

    expect(limiter.tryAcquire("10.0.0.1").allowed).toBe(true);
  });
});
