// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RequestNormalizer } from "../../../../packages/client-sdk/src/domain/service/request-normalizer.js";

describe("RequestNormalizer", () => {
  it("sends 2 dummy requests when Tier 2 made 2 real requests", async () => {
    let dummyCount = 0;
    const normalizer = new RequestNormalizer(async () => { dummyCount++; });
    await normalizer.normalize(2); // Tier 2: 2 real
    expect(dummyCount).toBe(2); // 4 - 2 = 2 dummies
  });

  it("sends 1 dummy request when Tier 0 made 3 real requests", async () => {
    let dummyCount = 0;
    const normalizer = new RequestNormalizer(async () => { dummyCount++; });
    await normalizer.normalize(3); // Tier 0: 3 real
    expect(dummyCount).toBe(1); // 4 - 3 = 1 dummy
  });

  it("sends 0 dummy requests when Tier 1 made 4 real requests", async () => {
    let dummyCount = 0;
    const normalizer = new RequestNormalizer(async () => { dummyCount++; });
    await normalizer.normalize(4); // Tier 1: 4 real
    expect(dummyCount).toBe(0); // already at target
  });

  it("all tiers result in exactly 4 total requests", async () => {
    for (const realCount of [2, 3, 4]) {
      let total = realCount;
      const normalizer = new RequestNormalizer(async () => { total++; });
      await normalizer.normalize(realCount);
      expect(total).toBe(4);
    }
  });
});
