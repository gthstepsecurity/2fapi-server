// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  DetectCompromise,
  DetectCompromiseRequest,
  DetectCompromiseResponse,
} from "../../domain/port/incoming/detect-compromise.js";
import type { IpBindingStore } from "../../domain/port/outgoing/ip-binding-store.js";
import type { GeoIpLookup } from "../../domain/port/outgoing/geo-ip-lookup.js";
import type { ClientSuspender } from "../../domain/port/outgoing/client-suspender.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { AuditLogStore } from "../../domain/port/outgoing/audit-log-store.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import {
  CompromiseDetectionEngine,
  type CompromiseAnomalyResult,
} from "../../domain/service/compromise-detection-engine.js";
import type { CompromiseDetectionConfig } from "../../domain/model/compromise-detection-config.js";
import { IpBinding } from "../../domain/model/ip-binding.js";
import { ClientSuspended } from "../../domain/event/client-suspended.js";
import { AuditEntry } from "../../domain/model/audit-entry.js";
import { AuditEventType } from "../../domain/model/audit-event-type.js";
import type { SuspensionReasonValue } from "../../domain/model/suspension-reason.js";

/**
 * Detects compromise indicators after an authentication event.
 * Checks concurrent sessions and geographic impossibility.
 * If anomaly detected and auto-suspend enabled, suspends the client.
 */
export class DetectCompromiseUseCase implements DetectCompromise {
  constructor(
    private readonly engine: CompromiseDetectionEngine,
    private readonly ipBindingStore: IpBindingStore,
    private readonly geoIpLookup: GeoIpLookup,
    private readonly clientSuspender: ClientSuspender,
    private readonly eventPublisher: EventPublisher,
    private readonly auditLogStore: AuditLogStore,
    private readonly clock: Clock,
    private readonly idGenerator: IdGenerator,
    private readonly config: CompromiseDetectionConfig,
  ) {}

  async execute(request: DetectCompromiseRequest): Promise<DetectCompromiseResponse> {
    if (!this.config.ipBindingEnabled) {
      return { anomalyDetected: false, suspended: false, reason: null };
    }

    const previousBinding = await this.ipBindingStore.findLatestByClientIdentifier(
      request.clientIdentifier,
    );

    // Record the current IP binding
    const newBinding = IpBinding.create(
      request.clientIdentifier,
      request.sourceIp,
      request.timestampMs,
    );
    await this.ipBindingStore.save(newBinding);

    if (previousBinding === null) {
      return { anomalyDetected: false, suspended: false, reason: null };
    }

    // Check concurrent session (different IP within time window)
    const timeDelta = request.timestampMs - previousBinding.boundAtMs;
    const concurrentResult = this.engine.detectConcurrentSession(
      request.clientIdentifier,
      previousBinding.sourceIp,
      request.sourceIp,
      timeDelta,
      this.config,
    );

    if (concurrentResult !== null) {
      return this.handleAnomaly(request, concurrentResult, "concurrent_session");
    }

    // Check geographic impossibility (if outside concurrent window, use geo check)
    const geoResult = await this.checkGeographicImpossibility(
      previousBinding.sourceIp,
      request.sourceIp,
      timeDelta,
    );

    if (geoResult !== null) {
      return this.handleAnomaly(request, geoResult, "geographic_impossibility");
    }

    return { anomalyDetected: false, suspended: false, reason: null };
  }

  private async checkGeographicImpossibility(
    previousIp: string,
    currentIp: string,
    timeDeltaMs: number,
  ): Promise<CompromiseAnomalyResult | null> {
    const loc1 = await this.geoIpLookup.lookup(previousIp);
    if (loc1 === null) {
      return null;
    }

    const loc2 = await this.geoIpLookup.lookup(currentIp);
    if (loc2 === null) {
      return null;
    }

    return this.engine.detectGeographicImpossibility(loc1, loc2, timeDeltaMs, this.config);
  }

  private async handleAnomaly(
    request: DetectCompromiseRequest,
    anomalyResult: CompromiseAnomalyResult,
    reason: SuspensionReasonValue,
  ): Promise<DetectCompromiseResponse> {
    if (!this.config.autoSuspendOnAnomaly) {
      return { anomalyDetected: true, suspended: false, reason: null };
    }

    await this.clientSuspender.suspend(request.clientIdentifier, reason);

    const nowMs = this.clock.nowMs();

    await this.eventPublisher.publish(
      new ClientSuspended(
        request.clientIdentifier,
        reason,
        nowMs,
        anomalyResult.details,
      ),
    );

    const auditEntry = AuditEntry.create({
      id: this.idGenerator.generate(),
      eventType: AuditEventType.from("auto_suspension"),
      clientIdentifier: request.clientIdentifier,
      timestampMs: nowMs,
      sourceAddress: request.sourceIp,
      details: {
        reason,
        anomalyType: anomalyResult.anomalyType,
      },
    });
    await this.auditLogStore.append(auditEntry);

    return { anomalyDetected: true, suspended: true, reason };
  }
}
