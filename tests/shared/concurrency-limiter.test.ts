// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ConcurrencyLimiter } from "../../src/shared/concurrency-limiter.js";

describe("ConcurrencyLimiter", () => {
  it("rejects maxConcurrent <= 0", () => {
    expect(() => new ConcurrencyLimiter(0)).toThrow("maxConcurrent must be a positive integer");
    expect(() => new ConcurrencyLimiter(-1)).toThrow("maxConcurrent must be a positive integer");
  });

  it("allows acquisitions up to maxConcurrent", () => {
    const limiter = new ConcurrencyLimiter(3);

    expect(limiter.acquire()).toBe(true);
    expect(limiter.acquire()).toBe(true);
    expect(limiter.acquire()).toBe(true);
    expect(limiter.activeCount).toBe(3);
  });

  it("rejects acquisition when at capacity", () => {
    const limiter = new ConcurrencyLimiter(2);

    limiter.acquire();
    limiter.acquire();

    expect(limiter.acquire()).toBe(false);
    expect(limiter.activeCount).toBe(2);
  });

  it("allows acquisition after release", () => {
    const limiter = new ConcurrencyLimiter(1);

    limiter.acquire();
    expect(limiter.acquire()).toBe(false);

    limiter.release();
    expect(limiter.acquire()).toBe(true);
  });

  it("release does not go below 0", () => {
    const limiter = new ConcurrencyLimiter(1);

    limiter.release();
    limiter.release();

    expect(limiter.activeCount).toBe(0);
  });

  it("11 concurrent attempts with maxConcurrent=10: 10 proceed, 1 rejected", () => {
    const limiter = new ConcurrencyLimiter(10);
    let accepted = 0;
    let rejected = 0;

    for (let i = 0; i < 11; i++) {
      if (limiter.acquire()) {
        accepted++;
      } else {
        rejected++;
      }
    }

    expect(accepted).toBe(10);
    expect(rejected).toBe(1);
  });
});
