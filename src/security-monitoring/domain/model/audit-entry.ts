// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditEventType } from "./audit-event-type.js";

const SENSITIVE_FIELDS = new Set(["secret", "blinding", "proof", "privateKey", "blindingFactor"]);

export interface AuditEntryInput {
  readonly id: string;
  readonly eventType: AuditEventType;
  /**
   * @pii This field contains a plaintext client identifier.
   * Audit logs containing this field MUST be access-controlled.
   * Only authorized administrators should have read access to audit logs.
   * Consider hashing before export to external systems.
   */
  readonly clientIdentifier: string;
  readonly timestampMs: number;
  /**
   * @pii This field contains the source IP address.
   * Audit logs containing this field MUST be access-controlled.
   */
  readonly sourceAddress: string;
  readonly details: Record<string, string>;
}

/**
 * Immutable audit log entry. Never contains secrets.
 * Frozen at creation to prevent external mutation.
 *
 * WARNING (T-10): This entry contains PII fields (clientIdentifier, sourceAddress).
 * Audit log storage and access MUST be restricted to authorized personnel only.
 * See PROTOCOL.md for data protection requirements.
 */
export class AuditEntry {
  readonly id: string;
  readonly eventType: AuditEventType;
  /** @pii Plaintext client identifier — access-controlled field */
  readonly clientIdentifier: string;
  readonly timestampMs: number;
  /** @pii Source IP address — access-controlled field */
  readonly sourceAddress: string;
  readonly details: Readonly<Record<string, string>>;

  private constructor(input: AuditEntryInput) {
    this.id = input.id;
    this.eventType = input.eventType;
    this.clientIdentifier = input.clientIdentifier;
    this.timestampMs = input.timestampMs;
    this.sourceAddress = input.sourceAddress;
    this.details = Object.freeze({ ...input.details });
    Object.freeze(this);
  }

  static create(input: AuditEntryInput): AuditEntry {
    if (input.id.length === 0) {
      throw new Error("Audit entry ID must not be empty");
    }
    AuditEntry.validateNoSensitiveFields(input.details);
    return new AuditEntry(input);
  }

  private static validateNoSensitiveFields(details: Record<string, string>): void {
    for (const key of Object.keys(details)) {
      if (SENSITIVE_FIELDS.has(key)) {
        throw new Error("Audit entry must not contain sensitive fields");
      }
    }
  }
}
