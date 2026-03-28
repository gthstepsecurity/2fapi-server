// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

// The commitment value is intentionally omitted from this event
// to prevent propagation of cryptographic material through the event bus.

export class CommitmentRotated implements DomainEvent {
  readonly eventType = "CommitmentRotated";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly commitmentVersion: number,
  ) {
    this.occurredAt = new Date();
  }
}
