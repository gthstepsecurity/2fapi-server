// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryIpRateLimiter } from "../../src/api-gateway/middleware/ip-rate-limiter.js";

describe("FIX 4 — IP Rate Limiter Map Unbounded", () => {
  it("rejects new IP when map is at maxEntries", () => {
    const limiter = new InMemoryIpRateLimiter(100, 60_000, 3);

    // Fill up 3 slots
    limiter.tryAcquire("1.1.1.1");
    limiter.tryAcquire("2.2.2.2");
    limiter.tryAcquire("3.3.3.3");

    // 4th new IP should be rejected
    const result = limiter.tryAcquire("4.4.4.4");
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("allows existing IP at maxEntries to continue", () => {
    const limiter = new InMemoryIpRateLimiter(100, 60_000, 3);

    limiter.tryAcquire("1.1.1.1");
    limiter.tryAcquire("2.2.2.2");
    limiter.tryAcquire("3.3.3.3");

    // Existing IP should still be allowed
    const result = limiter.tryAcquire("1.1.1.1");
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(98); // 100 - 2 (already used 1 + this request)
  });

  it("uses default maxEntries of 10000 when not specified", () => {
    const limiter = new InMemoryIpRateLimiter(100, 60_000);

    // Should accept at least the first IP without issue
    const result = limiter.tryAcquire("1.1.1.1");
    expect(result.allowed).toBe(true);
  });

  it("window reset clears entries and allows new IPs again", () => {
    const limiter = new InMemoryIpRateLimiter(100, 60_000, 2);

    limiter.tryAcquire("1.1.1.1");
    limiter.tryAcquire("2.2.2.2");

    // At capacity — new IP rejected
    const rejected = limiter.tryAcquire("3.3.3.3");
    expect(rejected.allowed).toBe(false);

    // Reset window
    limiter.resetWindow();

    // Now new IP should be accepted
    const accepted = limiter.tryAcquire("3.3.3.3");
    expect(accepted.allowed).toBe(true);
  });
});
