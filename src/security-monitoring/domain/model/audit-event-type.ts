// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Known audit event types in the Security Monitoring bounded context.
 */
export const KNOWN_AUDIT_EVENT_TYPES = [
  "enrollment_success",
  "enrollment_failure",
  "authentication_success",
  "authentication_failure",
  "challenge_issued",
  "challenge_expired",
  "client_locked_out",
  "client_unlocked",
  "token_issued",
  "token_validation_success",
  "token_validation_failure",
  "client_revoked",
  "anomaly_detected",
  "audit_tampering_attempt",
  "auto_suspension",
  "ip_binding_violation",
  "geographic_impossibility_suspension",
] as const;

export type KnownAuditEventType = typeof KNOWN_AUDIT_EVENT_TYPES[number];

const KNOWN_SET: ReadonlySet<string> = new Set(KNOWN_AUDIT_EVENT_TYPES);

/**
 * Value object representing an audit event type.
 * Unknown event types are recorded as "unknown_event" with the original value preserved.
 */
export class AuditEventType {
  private constructor(
    readonly value: string,
    readonly isKnown: boolean,
    readonly originalValue: string | null,
  ) {}

  static from(eventType: string): AuditEventType {
    if (eventType.length === 0) {
      throw new Error("Event type must not be empty");
    }
    if (KNOWN_SET.has(eventType)) {
      return new AuditEventType(eventType, true, null);
    }
    return new AuditEventType("unknown_event", false, eventType);
  }

  equals(other: AuditEventType): boolean {
    return this.value === other.value && this.originalValue === other.originalValue;
  }
}
