// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ClientStatusChecker,
  LockoutInfo,
} from "../../../domain/port/outgoing/client-status-checker.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape from the failed_attempts table.
 */
interface AttemptRow {
  consecutive_failures: number;
  locked_out_at_ms: string | null;
}

/**
 * PostgreSQL-backed client status checker for the Authentication Challenge context.
 *
 * Cross-context bridge: queries the failed_attempts table (owned by Security Monitoring)
 * to determine lockout status and failed attempt count for a client.
 *
 * Also records failed attempts by upserting the failed_attempts counter.
 */
export class PgClientStatusBridge implements ClientStatusChecker {
  constructor(
    private readonly db: DatabaseClient,
    private readonly lockoutDurationMs: number = 900_000,
  ) {}

  async getLockoutInfo(clientIdentifier: string): Promise<LockoutInfo> {
    try {
      const result = await this.db.query(
        "SELECT consecutive_failures, locked_out_at_ms FROM failed_attempts WHERE client_identifier = $1",
        [clientIdentifier],
      );

      if (result.rows.length === 0) {
        return { isLockedOut: false, failedAttempts: 0 };
      }

      const row = result.rows[0] as AttemptRow;
      const failedAttempts = row.consecutive_failures;
      const lockedOutAtMs = row.locked_out_at_ms !== null
        ? Number(row.locked_out_at_ms)
        : null;

      // Check if lockout has expired
      const isLockedOut = lockedOutAtMs !== null &&
        (Date.now() - lockedOutAtMs) < this.lockoutDurationMs;

      return { isLockedOut, failedAttempts };
    } catch {
      // Fail-closed: when the database is unavailable, treat all clients
      // as locked out to prevent attackers from bypassing lockout
      // by overloading the database
      return { isLockedOut: true, failedAttempts: 999 };
    }
  }

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
}
