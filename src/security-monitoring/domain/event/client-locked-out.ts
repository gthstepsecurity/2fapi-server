// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

/**
 * Integration event published when a client is locked out after exceeding
 * the failed attempt threshold. Consumed by other bounded contexts
 * (e.g., Authentication Challenge) to refuse new challenges.
 * Does NOT disclose lockout duration (NIST AAL2 compliance).
 */
export class ClientLockedOut implements DomainEvent {
  readonly eventType = "ClientLockedOut";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly lockedOutAtMs: number,
    readonly consecutiveFailures: number,
  ) {
    this.occurredAt = new Date(lockedOutAtMs);
  }
}
