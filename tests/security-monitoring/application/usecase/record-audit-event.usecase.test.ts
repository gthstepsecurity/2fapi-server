// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RecordAuditEventUseCase } from "../../../../src/security-monitoring/application/usecase/record-audit-event.usecase.js";
import { InMemoryAuditLogStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../../../src/security-monitoring/domain/port/outgoing/id-generator.js";
import type { AlertDispatcher } from "../../../../src/security-monitoring/domain/port/outgoing/alert-dispatcher.js";
import type { AnomalyAlert } from "../../../../src/security-monitoring/domain/model/anomaly-alert.js";

function createStubIdGenerator(): IdGenerator {
  let counter = 0;
  return {
    generate(): string {
      counter++;
      return `entry-${String(counter).padStart(3, "0")}`;
    },
  };
}

function createCapturingAlertDispatcher(): AlertDispatcher & { alerts: AnomalyAlert[] } {
  const dispatcher: AlertDispatcher & { alerts: AnomalyAlert[] } = {
    alerts: [],
    async dispatch(alert: AnomalyAlert): Promise<void> {
      dispatcher.alerts.push(alert);
    },
  };
  return dispatcher;
}

describe("RecordAuditEventUseCase", () => {
  let store: InMemoryAuditLogStore;
  let clock: Clock;
  let idGen: IdGenerator;
  let alertDispatcher: ReturnType<typeof createCapturingAlertDispatcher>;
  let useCase: RecordAuditEventUseCase;

  beforeEach(() => {
    store = new InMemoryAuditLogStore();
    clock = { nowMs: () => 1700000000000 };
    idGen = createStubIdGenerator();
    alertDispatcher = createCapturingAlertDispatcher();
    useCase = new RecordAuditEventUseCase(store, clock, idGen, alertDispatcher);
  });

  it("records a known event type", async () => {
    const result = await useCase.execute({
      eventType: "authentication_success",
      clientIdentifier: "alice-payment-service",
      sourceAddress: "192.168.1.1",
      details: { challengeId: "ch-001" },
    });

    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.entryId).toBe("entry-001");
    }

    const entries = await store.findAll();
    expect(entries.length).toBe(1);
    expect(entries[0]!.eventType.value).toBe("authentication_success");
    expect(entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(entries[0]!.sourceAddress).toBe("192.168.1.1");
  });

  it("records unknown event type as 'unknown_event' and generates alert", async () => {
    const result = await useCase.execute({
      eventType: "some_random_event",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: {},
    });

    expect(result.recorded).toBe(true);
    const entries = await store.findAll();
    expect(entries[0]!.eventType.value).toBe("unknown_event");
    expect(entries[0]!.eventType.isKnown).toBe(false);
    expect(entries[0]!.eventType.originalValue).toBe("some_random_event");
    expect(alertDispatcher.alerts.length).toBe(1);
    const alert = alertDispatcher.alerts[0]!;
    expect(alert.details.reason).toBe("unknown_event_type");
    expect(alert.details.originalEventType).toBe("some_random_event");
    expect(alert.details.clientIdentifier).toBe("alice");
    expect(alert.detectedAtMs).toBe(1700000000000);
  });

  it("rejects entry with sensitive fields", async () => {
    const result = await useCase.execute({
      eventType: "authentication_failure",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: { secret: "my-secret-value" },
    });

    expect(result.recorded).toBe(false);
    if (!result.recorded) {
      expect(result.error).toBe("invalid_event");
    }
  });

  it("returns error when store is unavailable", async () => {
    const failingStore: InMemoryAuditLogStore = new InMemoryAuditLogStore();
    failingStore.setUnavailable(true);
    const failingUseCase = new RecordAuditEventUseCase(failingStore, clock, idGen, alertDispatcher);

    const result = await failingUseCase.execute({
      eventType: "authentication_success",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: {},
    });

    expect(result.recorded).toBe(false);
    if (!result.recorded) {
      expect(result.error).toBe("audit_unavailable");
    }
  });

  it("handles high-volume events (10K)", async () => {
    const promises: Promise<unknown>[] = [];
    for (let i = 0; i < 10000; i++) {
      promises.push(
        useCase.execute({
          eventType: "authentication_success",
          clientIdentifier: `client-${i}`,
          sourceAddress: "10.0.0.1",
          details: {},
        }),
      );
    }
    await Promise.all(promises);

    const count = await store.count();
    expect(count).toBe(10000);
  });

  it("entry includes correct timestamp from clock", async () => {
    await useCase.execute({
      eventType: "enrollment_success",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: {},
    });

    const entries = await store.findAll();
    expect(entries[0]!.timestampMs).toBe(1700000000000);
  });

  it("entry does NOT include any secret values", async () => {
    await useCase.execute({
      eventType: "authentication_failure",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: { reason: "invalid_proof", attemptCount: "3" },
    });

    const entries = await store.findAll();
    const entry = entries[0]!;
    expect(entry.details).not.toHaveProperty("secret");
    expect(entry.details).not.toHaveProperty("blinding");
    expect(entry.details).not.toHaveProperty("proof");
  });

  it("does NOT generate alert for known event types", async () => {
    // Kill mutant: `if (true)` instead of `if (!eventType.isKnown)`
    await useCase.execute({
      eventType: "authentication_success",
      clientIdentifier: "alice",
      sourceAddress: "10.0.0.1",
      details: {},
    });

    // Known event type should NOT trigger an alert
    expect(alertDispatcher.alerts.length).toBe(0);
  });
});
