// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

// The nonce and credential are intentionally omitted from this event
// to prevent propagation of security-sensitive material through the event bus.

export class ChallengeIssued implements DomainEvent {
  readonly eventType = "ChallengeIssued";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly challengeReference: string,
    readonly expiresAtMs: number,
  ) {
    this.occurredAt = new Date();
  }
}
