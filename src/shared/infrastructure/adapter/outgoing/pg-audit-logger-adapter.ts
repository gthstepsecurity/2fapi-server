// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Generic audit entry shape used by authentication-challenge, zk-verification,
 * and api-access-control bounded contexts.
 *
 * All three contexts define the same AuditLogger interface:
 *   { log(entry: { action: string; clientIdentifier: string; timestamp: Date; details: Record<string, unknown> }): Promise<void> }
 */
export interface GenericAuditEntry {
  readonly action: string;
  readonly clientIdentifier: string;
  readonly timestamp: Date;
  readonly details: Record<string, unknown>;
}

export interface GenericAuditLogger {
  log(entry: GenericAuditEntry): Promise<void>;
}

/**
 * Adapts PgAuditLogStore to the per-context AuditLogger interface.
 *
 * Each bounded context (authentication-challenge, zk-verification, api-access-control)
 * defines its own AuditLogger with the same shape. This adapter bridges them all
 * to the underlying PostgreSQL audit_log table managed by Security Monitoring.
 *
 * Uses direct SQL inserts rather than depending on PgAuditLogStore to avoid
 * cross-module import of domain models (AuditEntry, AuditEventType).
 */
export class PgAuditLoggerAdapter implements GenericAuditLogger {
  constructor(
    private readonly db: DatabaseClient,
    private readonly contextPrefix: string,
  ) {}

  async log(entry: GenericAuditEntry): Promise<void> {
    try {
      const id = `${this.contextPrefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
      const nowMs = Date.now();
      const eventType = entry.action;

      await this.db.query(
        `INSERT INTO audit_log
         (id, event_type, event_type_known, original_event_type, client_identifier, timestamp_ms, source_address, details, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          id,
          eventType,
          true,
          null,
          entry.clientIdentifier,
          entry.timestamp.getTime(),
          "system",
          JSON.stringify(entry.details),
          nowMs,
          nowMs,
        ],
      );
    } catch {
      // Audit logging must never cause request failure.
      // Log to console as fallback.
      console.error(`[AUDIT-FALLBACK] ${entry.action} | client=${entry.clientIdentifier}`);
    }
  }
}
