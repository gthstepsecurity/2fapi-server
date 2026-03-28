// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";
import type { SuspensionReasonValue } from "../model/suspension-reason.js";

/**
 * Integration event published when a client is suspended due to a detected anomaly.
 * Consumed by other bounded contexts (e.g., Authentication Challenge, API Access Control)
 * to refuse operations for suspended clients.
 * Does NOT disclose the suspension reason to the client.
 */
export class ClientSuspended implements DomainEvent {
  readonly eventType = "ClientSuspended";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly reason: SuspensionReasonValue,
    readonly detectedAtMs: number,
    readonly details: Readonly<Record<string, unknown>>,
  ) {
    this.occurredAt = new Date(detectedAtMs);
  }
}
