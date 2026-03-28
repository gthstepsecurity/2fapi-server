// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RecordSuccessfulAuthUseCase } from "../../../../src/security-monitoring/application/usecase/record-successful-auth.usecase.js";
import { InMemoryAttemptCounterStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";

describe("RecordSuccessfulAuthUseCase", () => {
  const config = LockoutConfig.defaults();
  let store: InMemoryAttemptCounterStore;
  let useCase: RecordSuccessfulAuthUseCase;

  beforeEach(() => {
    store = new InMemoryAttemptCounterStore();
    useCase = new RecordSuccessfulAuthUseCase(store);
  });

  it("decrements counter by 1 on successful auth (BE08)", async () => {
    // Setup: 2 failed attempts
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    await store.save(counter);

    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);

    const updated = await store.findByClientIdentifier("alice");
    // BE08: decrements by 1, not resets to 0
    expect(updated!.consecutiveFailures).toBe(1);
  });

  it("handles client with no prior attempts", async () => {
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);

    const updated = await store.findByClientIdentifier("alice");
    expect(updated!.consecutiveFailures).toBe(0);
  });

  it("decrements locked-out client counter by 1 on successful auth (BE08)", async () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    counter = counter.increment(3000, config);
    await store.save(counter);

    await useCase.execute({ clientIdentifier: "alice" });

    const updated = await store.findByClientIdentifier("alice");
    // BE08: 3 failures - 1 = 2 failures remaining
    expect(updated!.consecutiveFailures).toBe(2);
  });

  it("prevents lockout evasion via success alternation (BE08)", async () => {
    // 2 failures → success → 2 more failures → should hit 3 total and lock out
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    await store.save(counter);

    // Success: 2 → 1
    await useCase.execute({ clientIdentifier: "alice" });
    const afterSuccess = await store.findByClientIdentifier("alice");
    expect(afterSuccess!.consecutiveFailures).toBe(1);

    // 2 more failures: 1 → 2 → 3 (locked!)
    let updated = afterSuccess!;
    updated = updated.increment(3000, config);
    updated = updated.increment(4000, config);
    await store.save(updated);

    const final = await store.findByClientIdentifier("alice");
    expect(final!.consecutiveFailures).toBe(3);
    expect(final!.isLockedOut(4000, config)).toBe(true);
  });
});
