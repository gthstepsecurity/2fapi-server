// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

export class ChallengeInvalidated implements DomainEvent {
  readonly eventType = "ChallengeInvalidated";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly challengeReference: string,
  ) {
    this.occurredAt = new Date();
  }
}
