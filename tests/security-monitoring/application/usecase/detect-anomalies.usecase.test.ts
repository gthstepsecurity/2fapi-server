// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { DetectAnomaliesUseCase } from "../../../../src/security-monitoring/application/usecase/detect-anomalies.usecase.js";
import { AnomalyDetectionEngine } from "../../../../src/security-monitoring/domain/service/anomaly-detection-engine.js";
import { InMemoryAuditLogStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { InMemoryAnomalyBaselineStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-anomaly-baseline-store.js";
import { InMemoryAttemptCounterStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import { AuditEntry } from "../../../../src/security-monitoring/domain/model/audit-entry.js";
import { AuditEventType } from "../../../../src/security-monitoring/domain/model/audit-event-type.js";
import { FailedAttemptCounter } from "../../../../src/security-monitoring/domain/model/failed-attempt-counter.js";
import { LockoutConfig } from "../../../../src/security-monitoring/domain/model/lockout-config.js";
import type { AlertDispatcher } from "../../../../src/security-monitoring/domain/port/outgoing/alert-dispatcher.js";
import type { AnomalyAlert } from "../../../../src/security-monitoring/domain/model/anomaly-alert.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../../../src/security-monitoring/domain/port/outgoing/id-generator.js";

function createStubIdGenerator(): IdGenerator {
  let counter = 0;
  return {
    generate(): string {
      counter++;
      return `alert-${String(counter).padStart(3, "0")}`;
    },
  };
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

const NOW_MS = 1700000000000;
const config = LockoutConfig.defaults();

describe("DetectAnomaliesUseCase", () => {
  let auditStore: InMemoryAuditLogStore;
  let baselineStore: InMemoryAnomalyBaselineStore;
  let counterStore: InMemoryAttemptCounterStore;
  let alertDispatcher: ReturnType<typeof createCapturingDispatcher>;
  let clock: Clock;
  let idGen: IdGenerator;
  let useCase: DetectAnomaliesUseCase;

  beforeEach(() => {
    auditStore = new InMemoryAuditLogStore();
    baselineStore = new InMemoryAnomalyBaselineStore();
    counterStore = new InMemoryAttemptCounterStore();
    alertDispatcher = createCapturingDispatcher();
    clock = { nowMs: () => NOW_MS };
    idGen = createStubIdGenerator();
    const engine = new AnomalyDetectionEngine();
    useCase = new DetectAnomaliesUseCase(
      engine, auditStore, baselineStore, counterStore,
      alertDispatcher, clock, idGen,
    );
  });

  async function addAuditEntries(count: number, eventType: string, clientPrefix: string, startMs: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      await auditStore.append(
        AuditEntry.create({
          id: `entry-${clientPrefix}-${i}`,
          eventType: AuditEventType.from(eventType),
          clientIdentifier: `${clientPrefix}-${i}`,
          timestampMs: startMs + i * 100,
          sourceAddress: `10.0.0.${i % 256}`,
          details: {},
        }),
      );
    }
  }

  async function addAuditEntriesSameClient(count: number, eventType: string, clientId: string, startMs: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      await auditStore.append(
        AuditEntry.create({
          id: `entry-${clientId}-${i}`,
          eventType: AuditEventType.from(eventType),
          clientIdentifier: clientId,
          timestampMs: startMs + i * 100,
          sourceAddress: "10.0.0.1",
          details: {},
        }),
      );
    }
  }

  it("detects distributed brute-force (50 clients in 1 minute)", async () => {
    await addAuditEntries(50, "authentication_failure", "client", NOW_MS - 30000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    expect(bruteForceAlerts.length).toBe(1);
    expect(alertDispatcher.alerts.length).toBeGreaterThanOrEqual(1);

    const alert = bruteForceAlerts[0]!;
    expect(alert.id).toBe("alert-001");
    expect(alert.detectedAtMs).toBe(NOW_MS);
    expect(alert.details.clientCount).toBe(50);
    expect(alert.details.timeWindowMs).toBe(60000);
    expect(alert.isCritical).toBe(true);
    expect(Array.isArray(alert.details.sourceAddresses)).toBe(true);
  });

  it("does not trigger distributed brute-force at 49 clients", async () => {
    await addAuditEntries(49, "authentication_failure", "client", NOW_MS - 30000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    expect(bruteForceAlerts.length).toBe(0);
  });

  it("detects volume anomaly (20x baseline)", async () => {
    await baselineStore.saveBaseline({ clientIdentifier: "alice", authsPerHour: 10 });
    await addAuditEntriesSameClient(200, "authentication_success", "alice", NOW_MS - 3500000);

    const result = await useCase.execute({ windowMs: 3600000 });
    const volumeAlerts = result.alerts.filter((a) => a.anomalyType === "volume_anomaly");
    expect(volumeAlerts.length).toBe(1);

    const alert = volumeAlerts[0]!;
    expect(alert.detectedAtMs).toBe(NOW_MS);
    expect(alert.details.clientIdentifier).toBe("alice");
    expect(alert.details.baseline).toBe(10);
    expect(alert.details.actual).toBe(200);
    expect(alert.details.multiplier).toBe(20);
    expect(alert.isCritical).toBe(false);
  });

  it("does not trigger volume anomaly within baseline", async () => {
    await baselineStore.saveBaseline({ clientIdentifier: "alice", authsPerHour: 100 });
    await addAuditEntriesSameClient(120, "authentication_success", "alice", NOW_MS - 3500000);

    const result = await useCase.execute({ windowMs: 3600000 });
    const volumeAlerts = result.alerts.filter((a) => a.anomalyType === "volume_anomaly");
    expect(volumeAlerts.length).toBe(0);
  });

  it("updates baseline after analysis", async () => {
    await baselineStore.saveBaseline({ clientIdentifier: "alice", authsPerHour: 100 });
    await addAuditEntriesSameClient(120, "authentication_success", "alice", NOW_MS - 3500000);

    await useCase.execute({ windowMs: 3600000 });
    const baseline = await baselineStore.getBaseline("alice");
    expect(baseline).not.toBeNull();
    // Baseline should have been updated with EMA: alpha=0.3
    // observedPerHour = (120 / 3600000) * 3600000 = 120
    // updatedBaseline = 100 * 0.7 + 120 * 0.3 = 70 + 36 = 106
    expect(baseline!.authsPerHour).toBeCloseTo(106, 0);
  });

  it("detects mass lockout (10 lockouts in 5 minutes)", async () => {
    for (let i = 0; i < 10; i++) {
      let counter = FailedAttemptCounter.create(`client-${i}`);
      counter = counter.increment(NOW_MS - 200000 + i * 1000, config);
      counter = counter.increment(NOW_MS - 200000 + i * 1000 + 100, config);
      counter = counter.increment(NOW_MS - 200000 + i * 1000 + 200, config);
      await counterStore.save(counter);
    }

    const result = await useCase.execute({ windowMs: 300000 });
    const massLockoutAlerts = result.alerts.filter((a) => a.anomalyType === "mass_lockout");
    expect(massLockoutAlerts.length).toBe(1);

    const alert = massLockoutAlerts[0]!;
    expect(alert.detectedAtMs).toBe(NOW_MS);
    expect(alert.details.lockoutCount).toBe(10);
    expect(alert.details.timeWindowMs).toBe(300000);
    expect(alert.isCritical).toBe(true);
  });

  it("anomaly system failure does not throw (non-blocking)", async () => {
    // Make audit store fail
    auditStore.setUnavailable(true);

    // Should not throw
    const result = await useCase.execute({ windowMs: 60000 });
    expect(result.alerts).toEqual([]);
  });

  it("dispatches alerts for detected anomalies", async () => {
    await addAuditEntries(50, "authentication_failure", "client", NOW_MS - 30000);

    await useCase.execute({ windowMs: 60000 });
    expect(alertDispatcher.alerts.length).toBeGreaterThanOrEqual(1);
    expect(alertDispatcher.alerts[0]!.anomalyType).toBe("distributed_brute_force");
    expect(alertDispatcher.alerts[0]!.id).toBe("alert-001");
  });

  it("uses default baseline of 10 when no historical data exists", async () => {
    // 200 events with no baseline = 20x default of 10 = triggers volume anomaly
    await addAuditEntriesSameClient(200, "authentication_success", "bob", NOW_MS - 3500000);

    const result = await useCase.execute({ windowMs: 3600000 });
    const volumeAlerts = result.alerts.filter((a) => a.anomalyType === "volume_anomaly");
    expect(volumeAlerts.length).toBe(1);
    expect(volumeAlerts[0]!.details.baseline).toBe(10);
  });

  it("does not trigger mass lockout at 9 lockouts", async () => {
    for (let i = 0; i < 9; i++) {
      let counter = FailedAttemptCounter.create(`client-${i}`);
      counter = counter.increment(NOW_MS - 200000 + i * 1000, config);
      counter = counter.increment(NOW_MS - 200000 + i * 1000 + 100, config);
      counter = counter.increment(NOW_MS - 200000 + i * 1000 + 200, config);
      await counterStore.save(counter);
    }

    const result = await useCase.execute({ windowMs: 300000 });
    const massLockoutAlerts = result.alerts.filter((a) => a.anomalyType === "mass_lockout");
    expect(massLockoutAlerts.length).toBe(0);
  });

  it("returns empty alerts when no events in window", async () => {
    const result = await useCase.execute({ windowMs: 60000 });
    expect(result.alerts).toEqual([]);
  });

  it("filters entries by window boundaries correctly", async () => {
    // Events BEFORE the window should not be counted
    await addAuditEntries(50, "authentication_failure", "old-client", NOW_MS - 120000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    expect(bruteForceAlerts.length).toBe(0);
  });

  it("uses exponential moving average with alpha=0.3 for baseline update", async () => {
    await baselineStore.saveBaseline({ clientIdentifier: "charlie", authsPerHour: 50 });
    await addAuditEntriesSameClient(10, "authentication_success", "charlie", NOW_MS - 3500000);

    await useCase.execute({ windowMs: 3600000 });
    const baseline = await baselineStore.getBaseline("charlie");
    expect(baseline).not.toBeNull();
    // observedPerHour = (10 / 3600000) * 3600000 = 10
    // updatedBaseline = 50 * 0.7 + 10 * 0.3 = 35 + 3 = 38
    expect(baseline!.authsPerHour).toBeCloseTo(38, 0);
  });

  // --- Mutation survivors: window boundary tests ---

  it("includes events at exactly windowStartMs (>= not >)", async () => {
    // Kill mutant: `e.timestampMs > windowStartMs` instead of `>= windowStartMs`
    // Event at exactly windowStartMs should be included
    const exactBoundaryMs = NOW_MS - 60000; // exactly at window start
    await auditStore.append(
      AuditEntry.create({
        id: "boundary-entry",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "boundary-client",
        timestampMs: exactBoundaryMs,
        sourceAddress: "10.0.0.1",
        details: {},
      }),
    );
    // Add 49 more to reach 50 total
    await addAuditEntries(49, "authentication_failure", "client", NOW_MS - 30000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    // With the boundary entry included, we should have 50 distinct clients
    expect(bruteForceAlerts.length).toBe(1);
  });

  it("includes events at exactly nowMs in window (<= not <)", async () => {
    // Kill mutant: `e.timestampMs <= nowMs` replaced by `true`
    // This is hard to kill directly, but we can verify that entries after nowMs are excluded
    // by adding entries in the future
    await addAuditEntries(50, "authentication_failure", "future-client", NOW_MS + 1000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    // Future events should be excluded
    expect(bruteForceAlerts.length).toBe(0);
  });

  it("only counts authentication_failure events for brute-force (not all events)", async () => {
    // Kill mutant: `.filter((e) => true)` instead of filtering by authentication_failure
    await addAuditEntries(50, "authentication_success", "success-client", NOW_MS - 30000);

    const result = await useCase.execute({ windowMs: 60000 });
    const bruteForceAlerts = result.alerts.filter((a) => a.anomalyType === "distributed_brute_force");
    // Success events should not trigger brute-force detection
    expect(bruteForceAlerts.length).toBe(0);
  });

  it("lockout window includes boundary timestamps (>= and <=)", async () => {
    // Kill mutants for lockout window filtering:
    // c.lockedOutAtMs >= windowStartMs, c.lockedOutAtMs <= windowEndMs
    // Create exactly 10 lockouts with timestamps at the window boundaries
    const windowStartMs = NOW_MS - 300000;
    for (let i = 0; i < 10; i++) {
      let counter = FailedAttemptCounter.create(`boundary-client-${i}`);
      // Lock at exactly windowStartMs + i (one at the boundary)
      const lockTime = windowStartMs + i * 1000;
      counter = counter.increment(lockTime, config);
      counter = counter.increment(lockTime + 1, config);
      counter = counter.increment(lockTime + 2, config);
      await counterStore.save(counter);
    }

    const result = await useCase.execute({ windowMs: 300000 });
    const massLockoutAlerts = result.alerts.filter((a) => a.anomalyType === "mass_lockout");
    expect(massLockoutAlerts.length).toBe(1);
  });

  it("lockout at exactly window start is included (>= not >)", async () => {
    // Kill mutant: `c.lockedOutAtMs > windowStartMs` instead of `>= windowStartMs`
    const windowStartMs = NOW_MS - 300000;
    for (let i = 0; i < 10; i++) {
      let counter = FailedAttemptCounter.create(`exact-start-${i}`);
      // All lock at exactly windowStartMs
      counter = counter.increment(windowStartMs, config);
      counter = counter.increment(windowStartMs + 1, config);
      counter = counter.increment(windowStartMs + 2, config);
      await counterStore.save(counter);
    }

    const result = await useCase.execute({ windowMs: 300000 });
    const massLockoutAlerts = result.alerts.filter((a) => a.anomalyType === "mass_lockout");
    expect(massLockoutAlerts.length).toBe(1);
  });

  it("lockout at exactly window end is included (<= not <)", async () => {
    // Kill mutant: `c.lockedOutAtMs < windowEndMs` instead of `<= windowEndMs`
    // The lockoutAtMs is set to the increment timestamp when threshold is reached.
    // We need lockouts with lockedOutAtMs exactly at NOW_MS (windowEnd)
    for (let i = 0; i < 10; i++) {
      // Use restore to set exact lockout timestamps
      const counter = FailedAttemptCounter.restore(`exact-end-${i}`, 3, NOW_MS);
      await counterStore.save(counter);
    }

    const result = await useCase.execute({ windowMs: 300000 });
    const massLockoutAlerts = result.alerts.filter((a) => a.anomalyType === "mass_lockout");
    expect(massLockoutAlerts.length).toBe(1);
  });
});
