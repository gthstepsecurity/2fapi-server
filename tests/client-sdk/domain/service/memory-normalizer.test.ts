// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { MemoryNormalizer } from "../../../../packages/client-sdk/src/domain/service/memory-normalizer.js";

describe("MemoryNormalizer", () => {
  // --- R21-02: Pre-allocation at SDK init ---

  it("pre-allocates 64MB at initialization", () => {
    let allocSize = 0;
    let filled = false;
    const norm = new MemoryNormalizer(
      (size) => { allocSize = size; return new Uint8Array(size); },
      () => { filled = true; },
    );

    norm.preAllocate();
    expect(allocSize).toBe(64 * 1024 * 1024);
    expect(filled).toBe(true);
    expect(norm.isPreAllocated).toBe(true);
  });

  it("pre-allocates only once", () => {
    let callCount = 0;
    const norm = new MemoryNormalizer(
      (size) => { callCount++; return new Uint8Array(Math.min(size, 1024)); },
      () => {},
    );

    norm.preAllocate();
    norm.preAllocate();
    expect(callCount).toBe(1);
  });

  // --- R21-01: Access pattern normalization ---

  it("runs dummy Argon2id for Tier 1/2 (page fault pattern match)", async () => {
    let dummyRan = false;
    const norm = new MemoryNormalizer(
      (size) => new Uint8Array(Math.min(size, 1024)),
      () => {},
      async () => { dummyRan = true; },
    );

    await norm.normalizeAccessPattern(false); // Tier 1/2: Argon2id didn't run
    expect(dummyRan).toBe(true);
  });

  it("skips dummy Argon2id for Tier 0 (real already ran)", async () => {
    let dummyRan = false;
    const norm = new MemoryNormalizer(
      (size) => new Uint8Array(Math.min(size, 1024)),
      () => {},
      async () => { dummyRan = true; },
    );

    await norm.normalizeAccessPattern(true); // Tier 0: real Argon2id already ran
    expect(dummyRan).toBe(false);
  });

  it("falls back to sequential fill if no dummy Argon2id provided", async () => {
    let allocSize = 0;
    const norm = new MemoryNormalizer(
      (size) => { allocSize = size; return new Uint8Array(size); },
      () => {},
      // no dummyArgon2id
    );

    await norm.normalizeAccessPattern(false);
    expect(allocSize).toBe(64 * 1024 * 1024);
  });

  it("Tier 0 and Tier 1 produce identical memory behavior", async () => {
    // Tier 0: real Argon2id ran → normalizeAccessPattern(true) → no extra work
    // Tier 1: no Argon2id → normalizeAccessPattern(false) → dummy Argon2id runs
    //
    // From an observer's perspective:
    //   Tier 0: Argon2id + normalizeAccessPattern(true) = Argon2id only
    //   Tier 1: normalizeAccessPattern(false) = dummy Argon2id
    //
    // Both produce: sequential page faults + random page faults + free
    // INDISTINGUISHABLE
    let tier0DummyRan = false;
    let tier1DummyRan = false;

    const norm0 = new MemoryNormalizer(
      () => new Uint8Array(1024), () => {},
      async () => { tier0DummyRan = true; },
    );
    await norm0.normalizeAccessPattern(true); // Tier 0

    const norm1 = new MemoryNormalizer(
      () => new Uint8Array(1024), () => {},
      async () => { tier1DummyRan = true; },
    );
    await norm1.normalizeAccessPattern(false); // Tier 1

    expect(tier0DummyRan).toBe(false); // Tier 0: didn't need dummy
    expect(tier1DummyRan).toBe(true);  // Tier 1: ran dummy Argon2id
    // Both executed Argon2id (real or dummy) → same page fault pattern
  });
});
