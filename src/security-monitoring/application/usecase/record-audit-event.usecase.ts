// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  RecordAuditEvent,
  RecordAuditEventRequest,
  RecordAuditEventResponse,
} from "../../domain/port/incoming/record-audit-event.js";
import type { AuditLogStore } from "../../domain/port/outgoing/audit-log-store.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { AlertDispatcher } from "../../domain/port/outgoing/alert-dispatcher.js";
import { AuditEntry } from "../../domain/model/audit-entry.js";
import { AuditEventType } from "../../domain/model/audit-event-type.js";
import { AnomalyAlert } from "../../domain/model/anomaly-alert.js";

/**
 * Records a security-relevant event in the append-only audit log.
 * Returns error if the store is unavailable (fail-safe advisory).
 * Generates an alert for unknown event types.
 */
export class RecordAuditEventUseCase implements RecordAuditEvent {
  constructor(
    private readonly auditLogStore: AuditLogStore,
    private readonly clock: Clock,
    private readonly idGenerator: IdGenerator,
    private readonly alertDispatcher: AlertDispatcher,
  ) {}

  async execute(request: RecordAuditEventRequest): Promise<RecordAuditEventResponse> {
    const eventType = AuditEventType.from(request.eventType);
    const entryId = this.idGenerator.generate();

    let entry: AuditEntry;
    try {
      entry = AuditEntry.create({
        id: entryId,
        eventType,
        clientIdentifier: request.clientIdentifier,
        timestampMs: this.clock.nowMs(),
        sourceAddress: request.sourceAddress,
        details: request.details,
      });
    } catch {
      return { recorded: false, error: "invalid_event" };
    }

    try {
      await this.auditLogStore.append(entry);
    } catch {
      return { recorded: false, error: "audit_unavailable" };
    }

    if (!eventType.isKnown) {
      await this.alertDispatcher.dispatch(
        AnomalyAlert.create({
          id: this.idGenerator.generate(),
          anomalyType: "revoked_client_activity", // using as generic alert mechanism
          detectedAtMs: this.clock.nowMs(),
          details: {
            reason: "unknown_event_type",
            originalEventType: eventType.originalValue,
            clientIdentifier: request.clientIdentifier,
          },
        }),
      );
    }

    return { recorded: true, entryId };
  }
}
