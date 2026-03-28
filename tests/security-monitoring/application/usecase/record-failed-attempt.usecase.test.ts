// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RecordFailedAttemptUseCase } from "../../../../src/security-monitoring/application/usecase/record-failed-attempt.usecase.js";
import { LockoutPolicy } from "../../../../src/security-monitoring/domain/service/lockout-policy.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { InMemoryAttemptCounterStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import type { EventPublisher, DomainEvent } from "../../../../src/security-monitoring/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";
import { ClientLockedOut } from "../../../../src/security-monitoring/domain/event/client-locked-out.js";

function createCapturingPublisher(): EventPublisher & { events: DomainEvent[] } {
  const pub: EventPublisher & { events: DomainEvent[] } = {
    events: [],
    async publish(event: DomainEvent): Promise<void> {
      pub.events.push(event);
    },
  };
  return pub;
}

describe("RecordFailedAttemptUseCase", () => {
  const config = LockoutConfig.defaults();
  let store: InMemoryAttemptCounterStore;
  let publisher: ReturnType<typeof createCapturingPublisher>;
  let clock: Clock;
  let useCase: RecordFailedAttemptUseCase;

  beforeEach(() => {
    store = new InMemoryAttemptCounterStore();
    publisher = createCapturingPublisher();
    clock = { nowMs: () => 1700000000000 };
    const policy = new LockoutPolicy(config);
    useCase = new RecordFailedAttemptUseCase(store, policy, publisher, clock);
  });

  it("increments counter from 0 to 1", async () => {
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.consecutiveFailures).toBe(1);
      expect(result.lockedOut).toBe(false);
    }
  });

  it("increments counter from 1 to 2", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.consecutiveFailures).toBe(2);
      expect(result.lockedOut).toBe(false);
    }
  });

  it("triggers lockout at threshold (3)", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.consecutiveFailures).toBe(3);
      expect(result.lockedOut).toBe(true);
    }
  });

  it("does not lock at 2 failures", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    const result = await useCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.lockedOut).toBe(false);
    }
  });

  it("publishes ClientLockedOut event when threshold reached", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });

    expect(publisher.events.length).toBe(1);
    const event = publisher.events[0] as ClientLockedOut;
    expect(event.eventType).toBe("ClientLockedOut");
    expect(event.clientIdentifier).toBe("alice");
    expect(event.consecutiveFailures).toBe(3);
    expect(event.lockedOutAtMs).toBe(1700000000000);
  });

  it("does not publish event again for 4th failure (already locked)", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });

    // Event should only be published once (at threshold crossing)
    expect(publisher.events.length).toBe(1);
  });

  it("does not publish event before threshold", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "alice" });
    expect(publisher.events.length).toBe(0);
  });

  it("persists counter in store", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    const counter = await store.findByClientIdentifier("alice");
    expect(counter).not.toBeNull();
    expect(counter!.consecutiveFailures).toBe(1);
  });

  it("handles multiple clients independently", async () => {
    await useCase.execute({ clientIdentifier: "alice" });
    await useCase.execute({ clientIdentifier: "bob" });
    await useCase.execute({ clientIdentifier: "alice" });

    const alice = await store.findByClientIdentifier("alice");
    const bob = await store.findByClientIdentifier("bob");
    expect(alice!.consecutiveFailures).toBe(2);
    expect(bob!.consecutiveFailures).toBe(1);
  });

  it("uses configurable threshold (5)", async () => {
    const customConfig = LockoutConfig.create(5, 60000);
    const customPolicy = new LockoutPolicy(customConfig);
    const customUseCase = new RecordFailedAttemptUseCase(store, customPolicy, publisher, clock);

    for (let i = 0; i < 4; i++) {
      const result = await customUseCase.execute({ clientIdentifier: "alice" });
      if (result.recorded) {
        expect(result.lockedOut).toBe(false);
      }
    }

    const result = await customUseCase.execute({ clientIdentifier: "alice" });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.lockedOut).toBe(true);
      expect(result.consecutiveFailures).toBe(5);
    }
  });
});
