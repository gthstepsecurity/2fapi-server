// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

/**
 * Published when an access token is successfully issued.
 * Consumed by Security Monitoring for audit trail.
 * Intentionally excludes the token itself to prevent
 * propagation of bearer credentials through the event bus.
 */
export class TokenIssued implements DomainEvent {
  readonly eventType = "TokenIssued";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly audience: string,
    readonly authenticationLevel: string,
    readonly tokenId: string,
    readonly issuedAtMs: number,
  ) {
    this.occurredAt = new Date();
  }
}
