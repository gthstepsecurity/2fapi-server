// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FailedAttemptTracker } from "../../../domain/port/outgoing/failed-attempt-tracker.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * PostgreSQL-backed failed attempt tracker for the ZK Verification context.
 *
 * Cross-context bridge: delegates to the failed_attempts table (owned by
 * Security Monitoring) to record and reset failed verification attempts.
 */
export class PgFailedAttemptBridge implements FailedAttemptTracker {
  constructor(private readonly db: DatabaseClient) {}

  async recordFailedAttempt(clientIdentifier: string): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `INSERT INTO failed_attempts (client_identifier, consecutive_failures, locked_out_at_ms, created_at, updated_at)
       VALUES ($1, 1, NULL, $2, $3)
       ON CONFLICT (client_identifier)
       DO UPDATE SET
         consecutive_failures = failed_attempts.consecutive_failures + 1,
         updated_at = EXCLUDED.updated_at`,
      [clientIdentifier, nowMs, nowMs],
    );
  }

  async resetFailedAttempts(clientIdentifier: string): Promise<void> {
    await this.db.query(
      `UPDATE failed_attempts
       SET consecutive_failures = 0, locked_out_at_ms = NULL, updated_at = $2
       WHERE client_identifier = $1`,
      [clientIdentifier, Date.now()],
    );
  }
}
