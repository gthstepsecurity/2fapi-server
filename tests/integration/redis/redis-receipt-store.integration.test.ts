// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

/**
 * Integration tests for RedisVerificationReceiptStore against a real Redis instance.
 *
 * Prerequisites:
 *   docker compose up -d redis
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("RedisVerificationReceiptStore [integration]", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let redis: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let store: any;

  beforeAll(async () => {
    const Redis = (await import("ioredis")).default;
    redis = new Redis({
      host: "localhost",
      port: 6379,
      password: "dev-password",
    });

    const { RedisVerificationReceiptStore } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/redis-verification-receipt-store.js"
    );
    // Use a short TTL (10 seconds) for testing
    store = new RedisVerificationReceiptStore(redis, 10);
  });

  afterAll(async () => {
    if (redis) {
      await redis.quit();
    }
  });

  beforeEach(async () => {
    await redis.flushdb();
  });

  it("should store and consume a receipt", async () => {
    await store.store("receipt-1", "client-a");
    const result = await store.consume("receipt-1");
    expect(result).toBe("client-a");
  });

  it("should return null for non-existent receipt", async () => {
    const result = await store.consume("non-existent");
    expect(result).toBeNull();
  });

  it("should not allow double consumption", async () => {
    await store.store("receipt-2", "client-b");

    const first = await store.consume("receipt-2");
    expect(first).toBe("client-b");

    const second = await store.consume("receipt-2");
    expect(second).toBeNull();
  });

  it("should isolate receipts by ID", async () => {
    await store.store("receipt-a", "client-1");
    await store.store("receipt-b", "client-2");

    const resultA = await store.consume("receipt-a");
    expect(resultA).toBe("client-1");

    const resultB = await store.consume("receipt-b");
    expect(resultB).toBe("client-2");
  });
});
