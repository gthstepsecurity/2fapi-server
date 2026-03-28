// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainEvent } from "../port/outgoing/event-publisher.js";

/**
 * Published when a zero-knowledge proof is successfully verified.
 * Consumed by API Access Control (token issuance) and Security Monitoring.
 * Intentionally excludes proof data and commitment to prevent
 * propagation of cryptographic material through the event bus.
 */
export class ProofVerified implements DomainEvent {
  readonly eventType = "ProofVerified";
  readonly occurredAt: Date;

  constructor(
    readonly clientIdentifier: string,
    readonly challengeId: string,
    readonly verifiedAtMs: number,
    verifiedAt: Date,
  ) {
    this.occurredAt = verifiedAt;
  }
}
