// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogger, AuditEvent } from "../../src/client-registration/domain/port/outgoing/audit-logger.js";
import type { EventPublisher, DomainEvent } from "../../src/client-registration/domain/port/outgoing/event-publisher.js";
import type { EnrollClientRequest } from "../../src/client-registration/domain/port/incoming/enroll-client.js";
import type { RateLimiter } from "../../src/client-registration/domain/port/outgoing/rate-limiter.js";

export function createCapturingAuditLogger(): AuditLogger & { events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  return {
    events,
    log: async (event: AuditEvent) => {
      events.push(event);
    },
  };
}

export function createCapturingEventPublisher(): EventPublisher & { events: DomainEvent[] } {
  const events: DomainEvent[] = [];
  return {
    events,
    publish: async (event: DomainEvent) => {
      events.push(event);
    },
  };
}

export function createNoopRateLimiter(): RateLimiter {
  return {
    isAllowed: async () => true,
  };
}

export function validRequest(
  identifier: string = "test-client-1",
  commitmentByte: number = 42,
): EnrollClientRequest {
  return {
    clientIdentifier: identifier,
    commitmentBytes: new Uint8Array(32).fill(commitmentByte),
    proofOfPossession: {
      announcement: new Uint8Array(32).fill(1),
      responseS: new Uint8Array(32).fill(2),
      responseR: new Uint8Array(32).fill(3),
    },
  };
}
