// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AttemptCounterStore } from "../../../domain/port/outgoing/attempt-counter-store.js";
import { FailedAttemptCounter } from "../../../domain/model/failed-attempt-counter.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * Row shape returned from the failed_attempts table.
 */
interface AttemptRow {
  client_identifier: string;
  consecutive_failures: number;
  locked_out_at_ms: string | null;
}

/**
 * PostgreSQL implementation of AttemptCounterStore.
 *
 * Uses UPSERT (INSERT ... ON CONFLICT) for save operations to handle
 * both creation and update of failed attempt counters atomically.
 */
export class PgAttemptCounterStore implements AttemptCounterStore {
  constructor(private readonly db: DatabaseClient) {}

  async findByClientIdentifier(clientIdentifier: string): Promise<FailedAttemptCounter | null> {
    const result = await this.db.query(
      "SELECT client_identifier, consecutive_failures, locked_out_at_ms FROM failed_attempts WHERE client_identifier = $1",
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.toDomain(result.rows[0] as AttemptRow);
  }

  async save(counter: FailedAttemptCounter): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `INSERT INTO failed_attempts (client_identifier, consecutive_failures, locked_out_at_ms, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (client_identifier)
       DO UPDATE SET
         consecutive_failures = EXCLUDED.consecutive_failures,
         locked_out_at_ms = EXCLUDED.locked_out_at_ms,
         updated_at = EXCLUDED.updated_at`,
      [
        counter.clientIdentifier,
        counter.consecutiveFailures,
        counter.lockedOutAtMs,
        nowMs,
        nowMs,
      ],
    );
  }

  async findAllLocked(): Promise<readonly FailedAttemptCounter[]> {
    const result = await this.db.query(
      "SELECT client_identifier, consecutive_failures, locked_out_at_ms FROM failed_attempts WHERE locked_out_at_ms IS NOT NULL",
    );

    return result.rows.map((row) => this.toDomain(row as AttemptRow));
  }

  private toDomain(row: AttemptRow): FailedAttemptCounter {
    const lockedOutAtMs = row.locked_out_at_ms !== null
      ? Number(row.locked_out_at_ms)
      : null;

    return FailedAttemptCounter.restore(
      row.client_identifier,
      row.consecutive_failures,
      lockedOutAtMs,
    );
  }
}
