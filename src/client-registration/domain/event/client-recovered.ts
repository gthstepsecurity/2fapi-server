// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

export type RecoveryMethod = "phrase" | "external_intervention";

export class ClientRecovered implements DomainEvent {
  readonly eventType = "ClientRecovered";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly recoveryMethod: RecoveryMethod,
    readonly recoveredAtMs: number,
  ) {
    this.occurredAt = new Date();
  }
}
