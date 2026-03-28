// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { CheckLockoutStatusUseCase } from "../../../../src/security-monitoring/application/usecase/check-lockout-status.usecase.js";
import { LockoutPolicy } from "../../../../src/security-monitoring/domain/service/lockout-policy.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { InMemoryAttemptCounterStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";

describe("CheckLockoutStatusUseCase", () => {
  const config = LockoutConfig.defaults();
  let store: InMemoryAttemptCounterStore;
  let currentTime: number;
  let clock: Clock;
  let useCase: CheckLockoutStatusUseCase;

  beforeEach(() => {
    store = new InMemoryAttemptCounterStore();
    currentTime = 1700000000000;
    clock = { nowMs: () => currentTime };
    const policy = new LockoutPolicy(config);
    useCase = new CheckLockoutStatusUseCase(store, policy, clock);
  });

  it("returns unlocked for client with no attempts", async () => {
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.status.isLocked).toBe(false);
    expect(result.consecutiveFailures).toBe(0);
  });

  it("returns unlocked for client with 2 failures", async () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(1000, config);
    counter = counter.increment(2000, config);
    await store.save(counter);

    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.status.isLocked).toBe(false);
    expect(result.consecutiveFailures).toBe(2);
  });

  it("returns locked for client at threshold within duration", async () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(currentTime - 30 * 60 * 1000, config);
    counter = counter.increment(currentTime - 30 * 60 * 1000 + 1000, config);
    counter = counter.increment(currentTime - 30 * 60 * 1000 + 2000, config);
    await store.save(counter);

    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.status.isLocked).toBe(true);
    expect(result.consecutiveFailures).toBe(3);
  });

  it("returns unlocked after lockout expiry (counter stays at 3)", async () => {
    const lockoutTime = currentTime - config.durationMs - 1;
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(lockoutTime - 2000, config);
    counter = counter.increment(lockoutTime - 1000, config);
    counter = counter.increment(lockoutTime, config);
    await store.save(counter);

    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.status.isLocked).toBe(false);
    expect(result.consecutiveFailures).toBe(3);
  });

  it("does not disclose remaining lockout duration in response", async () => {
    let counter = FailedAttemptCounter.create("alice");
    counter = counter.increment(currentTime - 10 * 60 * 1000, config);
    counter = counter.increment(currentTime - 10 * 60 * 1000 + 1000, config);
    counter = counter.increment(currentTime - 10 * 60 * 1000 + 2000, config);
    await store.save(counter);

    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.status.isLocked).toBe(true);
    // LockoutStatus has no remaining duration field — NIST AAL2 compliance
    expect(result.status).not.toHaveProperty("remainingMs");
    expect(result.status).not.toHaveProperty("expiresAt");
  });
});
