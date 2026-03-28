// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

export class ClientReactivated implements DomainEvent {
  readonly eventType = "ClientReactivated";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly adminIdentity: string,
    readonly reactivatedAtMs: number,
  ) {
    this.occurredAt = new Date();
  }
}
