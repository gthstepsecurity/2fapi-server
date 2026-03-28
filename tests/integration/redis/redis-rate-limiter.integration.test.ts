// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

/**
 * Integration tests for RedisRateLimiter against a real Redis instance.
 *
 * Prerequisites:
 *   docker compose up -d redis
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("RedisRateLimiter [integration]", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let redis: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let rateLimiter: any;

  const config = {
    maxRequests: 5,
    windowMs: 10_000,
    keyPrefix: "ratelimit:test:",
  };

  beforeAll(async () => {
    // Dynamic import to avoid requiring ioredis in unit test runs
    const Redis = (await import("ioredis")).default;
    redis = new Redis({
      host: "localhost",
      port: 6379,
      password: "dev-password",
    });

    const { RedisRateLimiter } = await import(
      "../../../src/shared/infrastructure/adapter/outgoing/redis-rate-limiter.js"
    );
    rateLimiter = new RedisRateLimiter(redis, config);
  });

  afterAll(async () => {
    if (redis) {
      await redis.quit();
    }
  });

  beforeEach(async () => {
    // Flush test keys
    const keys = await redis.keys("ratelimit:test:*");
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  });

  it("should allow requests under the limit", async () => {
    const result = await rateLimiter.isAllowed("client-a");
    expect(result).toBe(true);
  });

  it("should allow up to maxRequests within the window", async () => {
    for (let i = 0; i < config.maxRequests; i++) {
      const result = await rateLimiter.isAllowed("client-b");
      expect(result).toBe(true);
    }
  });

  it("should deny requests exceeding the limit", async () => {
    // Fill up the limit
    for (let i = 0; i < config.maxRequests; i++) {
      await rateLimiter.isAllowed("client-c");
    }

    // Next request should be denied
    const result = await rateLimiter.isAllowed("client-c");
    expect(result).toBe(false);
  });

  it("should isolate rate limits per client", async () => {
    // Fill up client-d
    for (let i = 0; i < config.maxRequests; i++) {
      await rateLimiter.isAllowed("client-d");
    }

    // client-e should still be allowed
    const result = await rateLimiter.isAllowed("client-e");
    expect(result).toBe(true);
  });
});
