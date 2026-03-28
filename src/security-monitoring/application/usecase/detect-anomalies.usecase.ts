// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  DetectAnomalies,
  DetectAnomaliesRequest,
  DetectAnomaliesResponse,
} from "../../domain/port/incoming/detect-anomalies.js";
import type { AuditLogStore } from "../../domain/port/outgoing/audit-log-store.js";
import type { AnomalyBaselineStore } from "../../domain/port/outgoing/anomaly-baseline-store.js";
import type { AttemptCounterStore } from "../../domain/port/outgoing/attempt-counter-store.js";
import type { AlertDispatcher } from "../../domain/port/outgoing/alert-dispatcher.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import { AnomalyDetectionEngine, type FailureRecord, type LockoutRecord } from "../../domain/service/anomaly-detection-engine.js";
import { AnomalyAlert } from "../../domain/model/anomaly-alert.js";

/** Default baseline when no historical data exists (auths per hour). */
const DEFAULT_BASELINE = 10;

/**
 * Analyzes recent events against baselines, generates and dispatches alerts.
 * Non-blocking: if analysis fails, returns empty alerts instead of throwing.
 */
export class DetectAnomaliesUseCase implements DetectAnomalies {
  constructor(
    private readonly engine: AnomalyDetectionEngine,
    private readonly auditLogStore: AuditLogStore,
    private readonly baselineStore: AnomalyBaselineStore,
    private readonly counterStore: AttemptCounterStore,
    private readonly alertDispatcher: AlertDispatcher,
    private readonly clock: Clock,
    private readonly idGenerator: IdGenerator,
  ) {}

  async execute(request: DetectAnomaliesRequest): Promise<DetectAnomaliesResponse> {
    try {
      return await this.analyzeInternal(request);
    } catch {
      // Non-blocking: anomaly detection failure must not block auth
      return { alerts: [] };
    }
  }

  private async analyzeInternal(request: DetectAnomaliesRequest): Promise<DetectAnomaliesResponse> {
    const nowMs = this.clock.nowMs();
    const windowStartMs = nowMs - request.windowMs;
    const alerts: AnomalyAlert[] = [];

    // 1. BG10: Use findRecent() instead of findAll() to avoid O(N) full scan
    const recentEntries = await this.auditLogStore.findRecent(
      windowStartMs,
      10000, // safety limit to prevent unbounded results
    );
    // Filter out future entries (findRecent may return entries > nowMs)
    const windowEntries = recentEntries.filter((e) => e.timestampMs <= nowMs);

    // 2. Distributed brute-force detection
    const failures: FailureRecord[] = windowEntries
      .filter((e) => e.eventType.value === "authentication_failure")
      .map((e) => ({
        clientIdentifier: e.clientIdentifier,
        timestampMs: e.timestampMs,
        sourceAddress: e.sourceAddress,
      }));

    const bruteForceResult = this.engine.analyzeFailures(failures, windowStartMs, nowMs);
    if (bruteForceResult !== null) {
      const alert = AnomalyAlert.create({
        id: this.idGenerator.generate(),
        anomalyType: bruteForceResult.anomalyType,
        detectedAtMs: nowMs,
        details: bruteForceResult.details,
      });
      alerts.push(alert);
    }

    // 3. Volume anomaly detection (per client)
    const clientAuthCounts = new Map<string, number>();
    for (const entry of windowEntries) {
      const count = clientAuthCounts.get(entry.clientIdentifier) ?? 0;
      clientAuthCounts.set(entry.clientIdentifier, count + 1);
    }

    for (const [clientId, count] of clientAuthCounts) {
      const baseline = await this.baselineStore.getBaseline(clientId);
      const baselinePerHour = baseline?.authsPerHour ?? DEFAULT_BASELINE;

      const volumeResult = this.engine.analyzeVolume(clientId, count, baselinePerHour);
      if (volumeResult !== null) {
        const alert = AnomalyAlert.create({
          id: this.idGenerator.generate(),
          anomalyType: volumeResult.anomalyType,
          detectedAtMs: nowMs,
          details: volumeResult.details,
        });
        alerts.push(alert);
      }

      // Update baseline with exponential moving average
      const updatedBaseline = this.calculateUpdatedBaseline(baselinePerHour, count, request.windowMs);
      await this.baselineStore.saveBaseline({
        clientIdentifier: clientId,
        authsPerHour: updatedBaseline,
      });
    }

    // 4. Mass lockout detection
    const lockoutRecords = await this.findRecentLockouts(windowStartMs, nowMs);
    const massLockoutResult = this.engine.analyzeLockouts(lockoutRecords, windowStartMs, nowMs);
    if (massLockoutResult !== null) {
      const alert = AnomalyAlert.create({
        id: this.idGenerator.generate(),
        anomalyType: massLockoutResult.anomalyType,
        detectedAtMs: nowMs,
        details: massLockoutResult.details,
      });
      alerts.push(alert);
    }

    // 5. Dispatch all alerts
    for (const alert of alerts) {
      await this.alertDispatcher.dispatch(alert);
    }

    return { alerts };
  }

  /**
   * Exponential moving average for baseline update.
   * alpha=0.3 gives 30% weight to new observation.
   */
  private calculateUpdatedBaseline(currentBaseline: number, observedCount: number, windowMs: number): number {
    const hourMs = 3600000;
    const observedPerHour = (observedCount / windowMs) * hourMs;
    const alpha = 0.3;
    return currentBaseline * (1 - alpha) + observedPerHour * alpha;
  }

  /**
   * Finds lockout records from the counter store that occurred within the window.
   */
  private async findRecentLockouts(windowStartMs: number, windowEndMs: number): Promise<LockoutRecord[]> {
    const allLocked = await this.counterStore.findAllLocked();
    return allLocked
      .filter((c) =>
        c.lockedOutAtMs !== null && c.lockedOutAtMs >= windowStartMs && c.lockedOutAtMs <= windowEndMs,
      )
      .map((c) => ({ clientIdentifier: c.clientIdentifier, lockedOutAtMs: c.lockedOutAtMs! }));
  }
}
