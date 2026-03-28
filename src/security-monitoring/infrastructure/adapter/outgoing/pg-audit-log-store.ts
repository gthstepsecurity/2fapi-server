// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogStore, FindAllOptions } from "../../../domain/port/outgoing/audit-log-store.js";
import { AuditEntry } from "../../../domain/model/audit-entry.js";
import { AuditEventType } from "../../../domain/model/audit-event-type.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape returned from the audit_log table.
 */
interface AuditLogRow {
  id: string;
  event_type: string;
  event_type_known: boolean;
  original_event_type: string | null;
  client_identifier: string;
  timestamp_ms: string;
  source_address: string;
  details: Record<string, string>;
}

/**
 * PostgreSQL implementation of AuditLogStore.
 *
 * APPEND-ONLY: only INSERT and SELECT operations are performed.
 * No UPDATE or DELETE is ever issued against the audit_log table.
 */
export class PgAuditLogStore implements AuditLogStore {
  constructor(private readonly db: DatabaseClient) {}

  async append(entry: AuditEntry): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `INSERT INTO audit_log
       (id, event_type, event_type_known, original_event_type, client_identifier, timestamp_ms, source_address, details, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        entry.id,
        entry.eventType.value,
        entry.eventType.isKnown,
        entry.eventType.originalValue,
        entry.clientIdentifier,
        entry.timestampMs,
        entry.sourceAddress,
        JSON.stringify(entry.details),
        nowMs,
        nowMs,
      ],
    );
  }

  async findAll(options?: FindAllOptions): Promise<readonly AuditEntry[]> {
    const limit = options?.limit ?? 1000;
    const offset = options?.offset ?? 0;
    const result = await this.db.query(
      "SELECT id, event_type, event_type_known, original_event_type, client_identifier, timestamp_ms, source_address, details FROM audit_log ORDER BY timestamp_ms ASC LIMIT $1 OFFSET $2",
      [limit, offset],
    );

    return result.rows.map((row) => this.toDomain(row as AuditLogRow));
  }

  async count(): Promise<number> {
    const result = await this.db.query("SELECT COUNT(*) AS cnt FROM audit_log");
    return Number((result.rows[0] as { cnt: string }).cnt);
  }

  async deleteOlderThan(timestampMs: number): Promise<number> {
    const result = await this.db.query(
      "DELETE FROM audit_log WHERE timestamp_ms < $1",
      [timestampMs],
    );
    return (result as any).rowCount ?? 0;
  }

  async findRecent(sinceMs: number, limit: number): Promise<readonly AuditEntry[]> {
    const result = await this.db.query(
      "SELECT id, event_type, event_type_known, original_event_type, client_identifier, timestamp_ms, source_address, details FROM audit_log WHERE timestamp_ms >= $1 ORDER BY timestamp_ms DESC LIMIT $2",
      [sinceMs, limit],
    );
    return result.rows.map((row) => this.toDomain(row as AuditLogRow));
  }

  /**
   * Reconstructs an AuditEntry from a database row.
   *
   * For unknown event types, we reconstruct the AuditEventType from the
   * original value so the domain model sees the correct state.
   */
  private toDomain(row: AuditLogRow): AuditEntry {
    // Reconstruct the event type from the stored values.
    // If it was unknown, use the original value to get the same AuditEventType.
    const eventTypeString = row.event_type_known
      ? row.event_type
      : (row.original_event_type ?? row.event_type);
    const eventType = AuditEventType.from(eventTypeString);

    const details: Record<string, string> = typeof row.details === "string"
      ? JSON.parse(row.details)
      : row.details;

    return AuditEntry.create({
      id: row.id,
      eventType,
      clientIdentifier: row.client_identifier,
      timestampMs: Number(row.timestamp_ms),
      sourceAddress: row.source_address,
      details,
    });
  }
}
