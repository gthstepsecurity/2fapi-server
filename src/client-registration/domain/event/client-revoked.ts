// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

export class ClientRevoked implements DomainEvent {
  readonly eventType = "ClientRevoked";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly adminIdentity: string,
  ) {
    this.occurredAt = new Date();
  }
}
