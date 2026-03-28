// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryAttemptCounterStore } from "../../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import { FailedAttemptCounter } from "../../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { LockoutConfig } from "../../../../../src/security-monitoring/domain/model/lockout-config.js";

describe("InMemoryAttemptCounterStore", () => {
  const config = LockoutConfig.defaults();

  it("returns null for unknown client", async () => {
    const store = new InMemoryAttemptCounterStore();
    expect(await store.findByClientIdentifier("unknown")).toBeNull();
  });

  it("saves and retrieves counter", async () => {
    const store = new InMemoryAttemptCounterStore();
    const counter = FailedAttemptCounter.create("alice").increment(1000, config);
    await store.save(counter);

    const found = await store.findByClientIdentifier("alice");
    expect(found).not.toBeNull();
    expect(found!.consecutiveFailures).toBe(1);
  });

  it("overwrites previous counter for same client", async () => {
    const store = new InMemoryAttemptCounterStore();
    const c1 = FailedAttemptCounter.create("alice").increment(1000, config);
    await store.save(c1);
    const c2 = c1.increment(2000, config);
    await store.save(c2);

    const found = await store.findByClientIdentifier("alice");
    expect(found!.consecutiveFailures).toBe(2);
  });

  it("findAllLocked returns locked counters only", async () => {
    const store = new InMemoryAttemptCounterStore();
    let locked = FailedAttemptCounter.create("alice");
    locked = locked.increment(1000, config);
    locked = locked.increment(2000, config);
    locked = locked.increment(3000, config);
    await store.save(locked);

    const unlocked = FailedAttemptCounter.create("bob").increment(1000, config);
    await store.save(unlocked);

    const allLocked = await store.findAllLocked();
    expect(allLocked.length).toBe(1);
    expect(allLocked[0]!.clientIdentifier).toBe("alice");
  });
});
