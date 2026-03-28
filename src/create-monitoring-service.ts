// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RecordFailedAttempt } from "./security-monitoring/domain/port/incoming/record-failed-attempt.js";
import type { RecordSuccessfulAuth } from "./security-monitoring/domain/port/incoming/record-successful-auth.js";
import type { CheckLockoutStatus } from "./security-monitoring/domain/port/incoming/check-lockout-status.js";
import type { RecordAuditEvent } from "./security-monitoring/domain/port/incoming/record-audit-event.js";
import type { DetectAnomalies } from "./security-monitoring/domain/port/incoming/detect-anomalies.js";
import type { AttemptCounterStore } from "./security-monitoring/domain/port/outgoing/attempt-counter-store.js";
import type { AuditLogStore } from "./security-monitoring/domain/port/outgoing/audit-log-store.js";
import type { AnomalyBaselineStore } from "./security-monitoring/domain/port/outgoing/anomaly-baseline-store.js";
import type { AlertDispatcher } from "./security-monitoring/domain/port/outgoing/alert-dispatcher.js";
import type { EventPublisher } from "./security-monitoring/domain/port/outgoing/event-publisher.js";
import type { Clock } from "./security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "./security-monitoring/domain/port/outgoing/id-generator.js";
import { LockoutConfig } from "./security-monitoring/domain/model/lockout-config.js";
import { LockoutPolicy } from "./security-monitoring/domain/service/lockout-policy.js";
import { AnomalyDetectionEngine } from "./security-monitoring/domain/service/anomaly-detection-engine.js";
import { RecordFailedAttemptUseCase } from "./security-monitoring/application/usecase/record-failed-attempt.usecase.js";
import { RecordSuccessfulAuthUseCase } from "./security-monitoring/application/usecase/record-successful-auth.usecase.js";
import { CheckLockoutStatusUseCase } from "./security-monitoring/application/usecase/check-lockout-status.usecase.js";
import { RecordAuditEventUseCase } from "./security-monitoring/application/usecase/record-audit-event.usecase.js";
import { DetectAnomaliesUseCase } from "./security-monitoring/application/usecase/detect-anomalies.usecase.js";

export interface MonitoringServiceDependencies {
  readonly counterStore: AttemptCounterStore;
  readonly auditLogStore: AuditLogStore;
  readonly baselineStore: AnomalyBaselineStore;
  readonly alertDispatcher: AlertDispatcher;
  readonly eventPublisher: EventPublisher;
  readonly clock: Clock;
  readonly idGenerator: IdGenerator;
  readonly lockoutThreshold?: number;
  readonly lockoutDurationMs?: number;
}

export interface MonitoringService {
  readonly recordFailedAttempt: RecordFailedAttempt;
  readonly recordSuccessfulAuth: RecordSuccessfulAuth;
  readonly checkLockoutStatus: CheckLockoutStatus;
  readonly recordAuditEvent: RecordAuditEvent;
  readonly detectAnomalies: DetectAnomalies;
}

export function createMonitoringService(deps: MonitoringServiceDependencies): MonitoringService {
  const lockoutConfig = deps.lockoutThreshold !== undefined || deps.lockoutDurationMs !== undefined
    ? LockoutConfig.create(
        deps.lockoutThreshold ?? 3,
        deps.lockoutDurationMs ?? 60 * 60 * 1000,
      )
    : LockoutConfig.defaults();

  const lockoutPolicy = new LockoutPolicy(lockoutConfig);
  const anomalyEngine = new AnomalyDetectionEngine();

  const recordFailedAttempt = new RecordFailedAttemptUseCase(
    deps.counterStore, lockoutPolicy, deps.eventPublisher, deps.clock,
  );

  const recordSuccessfulAuth = new RecordSuccessfulAuthUseCase(deps.counterStore);

  const checkLockoutStatus = new CheckLockoutStatusUseCase(
    deps.counterStore, lockoutPolicy, deps.clock,
  );

  const recordAuditEvent = new RecordAuditEventUseCase(
    deps.auditLogStore, deps.clock, deps.idGenerator, deps.alertDispatcher,
  );

  const detectAnomalies = new DetectAnomaliesUseCase(
    anomalyEngine, deps.auditLogStore, deps.baselineStore, deps.counterStore,
    deps.alertDispatcher, deps.clock, deps.idGenerator,
  );

  return {
    recordFailedAttempt,
    recordSuccessfulAuth,
    checkLockoutStatus,
    recordAuditEvent,
    detectAnomalies,
  };
}
