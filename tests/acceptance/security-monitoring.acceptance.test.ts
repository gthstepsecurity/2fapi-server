// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RecordFailedAttemptUseCase } from "../../src/security-monitoring/application/usecase/record-failed-attempt.usecase.js";
import { RecordSuccessfulAuthUseCase } from "../../src/security-monitoring/application/usecase/record-successful-auth.usecase.js";
import { CheckLockoutStatusUseCase } from "../../src/security-monitoring/application/usecase/check-lockout-status.usecase.js";
import { RecordAuditEventUseCase } from "../../src/security-monitoring/application/usecase/record-audit-event.usecase.js";
import { DetectAnomaliesUseCase } from "../../src/security-monitoring/application/usecase/detect-anomalies.usecase.js";
import { LockoutPolicy } from "../../src/security-monitoring/domain/service/lockout-policy.js";
import { LockoutConfig } from "../../src/security-monitoring/domain/model/lockout-config.js";
import { AnomalyDetectionEngine } from "../../src/security-monitoring/domain/service/anomaly-detection-engine.js";
import { InMemoryAttemptCounterStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import { InMemoryAuditLogStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { InMemoryAnomalyBaselineStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-anomaly-baseline-store.js";
import { ClientLockedOut } from "../../src/security-monitoring/domain/event/client-locked-out.js";
import type { EventPublisher, DomainEvent } from "../../src/security-monitoring/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../src/security-monitoring/domain/port/outgoing/id-generator.js";
import type { AlertDispatcher } from "../../src/security-monitoring/domain/port/outgoing/alert-dispatcher.js";
import type { AnomalyAlert } from "../../src/security-monitoring/domain/model/anomaly-alert.js";

function createCapturingPublisher(): EventPublisher & { events: DomainEvent[] } {
  const pub: EventPublisher & { events: DomainEvent[] } = {
    events: [],
    async publish(event: DomainEvent): Promise<void> {
      pub.events.push(event);
    },
  };
  return pub;
}

function createCapturingDispatcher(): AlertDispatcher & { alerts: AnomalyAlert[] } {
  const d: AlertDispatcher & { alerts: AnomalyAlert[] } = {
    alerts: [],
    async dispatch(alert: AnomalyAlert): Promise<void> {
      d.alerts.push(alert);
    },
  };
  return d;
}

function createIdGenerator(): IdGenerator {
  let counter = 0;
  return {
    generate(): string {
      counter++;
      return `id-${String(counter).padStart(4, "0")}`;
    },
  };
}

describe("Security Monitoring — Acceptance Tests", () => {
  const config = LockoutConfig.defaults();
  let currentTimeMs: number;
  let counterStore: InMemoryAttemptCounterStore;
  let auditLogStore: InMemoryAuditLogStore;
  let baselineStore: InMemoryAnomalyBaselineStore;
  let publisher: ReturnType<typeof createCapturingPublisher>;
  let alertDispatcher: ReturnType<typeof createCapturingDispatcher>;
  let clock: Clock;
  let idGen: IdGenerator;

  let recordFailedAttempt: RecordFailedAttemptUseCase;
  let recordSuccessfulAuth: RecordSuccessfulAuthUseCase;
  let checkLockoutStatus: CheckLockoutStatusUseCase;
  let recordAuditEvent: RecordAuditEventUseCase;
  let detectAnomalies: DetectAnomaliesUseCase;

  beforeEach(() => {
    currentTimeMs = 1700000000000;
    counterStore = new InMemoryAttemptCounterStore();
    auditLogStore = new InMemoryAuditLogStore();
    baselineStore = new InMemoryAnomalyBaselineStore();
    publisher = createCapturingPublisher();
    alertDispatcher = createCapturingDispatcher();
    clock = { nowMs: () => currentTimeMs };
    idGen = createIdGenerator();

    const lockoutPolicy = new LockoutPolicy(config);
    const anomalyEngine = new AnomalyDetectionEngine();

    recordFailedAttempt = new RecordFailedAttemptUseCase(counterStore, lockoutPolicy, publisher, clock);
    recordSuccessfulAuth = new RecordSuccessfulAuthUseCase(counterStore);
    checkLockoutStatus = new CheckLockoutStatusUseCase(counterStore, lockoutPolicy, clock);
    recordAuditEvent = new RecordAuditEventUseCase(auditLogStore, clock, idGen, alertDispatcher);
    detectAnomalies = new DetectAnomaliesUseCase(
      anomalyEngine, auditLogStore, baselineStore, counterStore,
      alertDispatcher, clock, idGen,
    );
  });

  describe("Full lockout lifecycle", () => {
    it("3 failures → lockout → expiry → retry → success → reset", async () => {
      // 3 consecutive failures
      await recordFailedAttempt.execute({ clientIdentifier: "alice" });
      await recordFailedAttempt.execute({ clientIdentifier: "alice" });
      const lockoutResult = await recordFailedAttempt.execute({ clientIdentifier: "alice" });
      expect(lockoutResult.recorded).toBe(true);
      if (lockoutResult.recorded) {
        expect(lockoutResult.lockedOut).toBe(true);
        expect(lockoutResult.consecutiveFailures).toBe(3);
      }

      // Verify locked
      let status = await checkLockoutStatus.execute({ clientIdentifier: "alice" });
      expect(status.status.isLocked).toBe(true);

      // ClientLockedOut event published
      expect(publisher.events.length).toBe(1);
      const lockedEvent = publisher.events[0] as ClientLockedOut;
      expect(lockedEvent.eventType).toBe("ClientLockedOut");

      // Advance past lockout duration (61 minutes)
      currentTimeMs += 61 * 60 * 1000;

      // Lockout expired — counter still at 3
      status = await checkLockoutStatus.execute({ clientIdentifier: "alice" });
      expect(status.status.isLocked).toBe(false);
      expect(status.consecutiveFailures).toBe(3);

      // Successful auth decrements counter by 1 (BE08: prevents lockout evasion)
      await recordSuccessfulAuth.execute({ clientIdentifier: "alice" });
      status = await checkLockoutStatus.execute({ clientIdentifier: "alice" });
      expect(status.status.isLocked).toBe(false);
      expect(status.consecutiveFailures).toBe(2); // 3 - 1 = 2 (not reset to 0)
    });
  });

  describe("Audit trail for complete auth lifecycle", () => {
    it("records enrollment, failure, and success events", async () => {
      // Record enrollment
      const enrollResult = await recordAuditEvent.execute({
        eventType: "enrollment_success",
        clientIdentifier: "alice-payment-service",
        sourceAddress: "192.168.1.1",
        details: {},
      });
      expect(enrollResult.recorded).toBe(true);

      // Record authentication failure
      const failResult = await recordAuditEvent.execute({
        eventType: "authentication_failure",
        clientIdentifier: "alice-payment-service",
        sourceAddress: "192.168.1.1",
        details: { reason: "invalid_proof", attemptCount: "1" },
      });
      expect(failResult.recorded).toBe(true);

      // Record authentication success
      const successResult = await recordAuditEvent.execute({
        eventType: "authentication_success",
        clientIdentifier: "alice-payment-service",
        sourceAddress: "192.168.1.1",
        details: { challengeId: "ch-001" },
      });
      expect(successResult.recorded).toBe(true);

      // Verify all entries
      const entries = await auditLogStore.findAll();
      expect(entries.length).toBe(3);

      const types = entries.map((e) => e.eventType.value);
      expect(types).toContain("enrollment_success");
      expect(types).toContain("authentication_failure");
      expect(types).toContain("authentication_success");

      // Verify no secrets
      for (const entry of entries) {
        expect(entry.details).not.toHaveProperty("secret");
        expect(entry.details).not.toHaveProperty("proof");
        expect(entry.details).not.toHaveProperty("blinding");
      }
    });
  });

  describe("Audit immutability", () => {
    it("audit entries cannot be modified after creation", async () => {
      await recordAuditEvent.execute({
        eventType: "authentication_success",
        clientIdentifier: "alice",
        sourceAddress: "10.0.0.1",
        details: { note: "original" },
      });

      const entries = await auditLogStore.findAll();
      expect(Object.isFrozen(entries[0])).toBe(true);
      expect(Object.isFrozen(entries[0]!.details)).toBe(true);
    });
  });

  describe("Audit fail-safe", () => {
    it("returns error when audit store is unavailable", async () => {
      auditLogStore.setUnavailable(true);
      const result = await recordAuditEvent.execute({
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
  });

  describe("Anomaly detection integration", () => {
    it("detects distributed brute-force from audit trail", async () => {
      // Record 50 failures from different clients
      for (let i = 0; i < 50; i++) {
        await recordAuditEvent.execute({
          eventType: "authentication_failure",
          clientIdentifier: `client-${i}`,
          sourceAddress: `10.0.0.${i % 256}`,
          details: {},
        });
      }

      const result = await detectAnomalies.execute({ windowMs: 60000 });
      const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
      expect(bruteForceAlerts.length).toBe(1);
    });

    it("anomaly detection failure does not throw", async () => {
      auditLogStore.setUnavailable(true);
      const result = await detectAnomalies.execute({ windowMs: 60000 });
      expect(result.alerts).toEqual([]);
    });
  });

  describe("Configurable lockout", () => {
    it("uses custom threshold and duration", async () => {
      const customConfig = LockoutConfig.create(5, 30 * 60 * 1000);
      const customPolicy = new LockoutPolicy(customConfig);
      const customRecordFailed = new RecordFailedAttemptUseCase(counterStore, customPolicy, publisher, clock);
      const customCheckStatus = new CheckLockoutStatusUseCase(counterStore, customPolicy, clock);

      // 4 failures — not locked
      for (let i = 0; i < 4; i++) {
        await customRecordFailed.execute({ clientIdentifier: "bob" });
      }
      let status = await customCheckStatus.execute({ clientIdentifier: "bob" });
      expect(status.status.isLocked).toBe(false);

      // 5th failure — locked
      await customRecordFailed.execute({ clientIdentifier: "bob" });
      status = await customCheckStatus.execute({ clientIdentifier: "bob" });
      expect(status.status.isLocked).toBe(true);

      // Expires after 30 min (not 60)
      currentTimeMs += 31 * 60 * 1000;
      status = await customCheckStatus.execute({ clientIdentifier: "bob" });
      expect(status.status.isLocked).toBe(false);
    });
  });
});
