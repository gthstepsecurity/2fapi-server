// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";
import type { AnomalyType } from "../model/anomaly-type.js";

/**
 * Integration event published when an anomaly is detected.
 * Consumed by alerting/escalation systems.
 */
export class AnomalyDetected implements DomainEvent {
  readonly eventType = "AnomalyDetected";
  readonly occurredAt: Date;

  constructor(
    readonly anomalyType: AnomalyType,
    readonly detectedAtMs: number,
    readonly isCritical: boolean,
    readonly details: Readonly<Record<string, unknown>>,
  ) {
    this.occurredAt = new Date(detectedAtMs);
  }
}
