// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientStatusChecker } from "../../../domain/port/outgoing/client-status-checker.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape from the clients table (subset for status check).
 */
interface ClientRow {
  status: string;
}

/**
 * PostgreSQL-backed client status checker for the API Access Control context.
 *
 * Cross-context bridge: queries the clients table (owned by Client Registration)
 * to determine whether a client is currently active. Called at every token
 * validation to ensure revoked clients are denied immediately.
 */
export class PgClientStatusBridge implements ClientStatusChecker {
  constructor(private readonly db: DatabaseClient) {}

  async isActive(clientIdentifier: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        "SELECT status FROM clients WHERE identifier = $1",
        [clientIdentifier],
      );

      if (result.rows.length === 0) {
        return false;
      }

      const row = result.rows[0] as ClientRow;
      return row.status === "active";
    } catch {
      // Fail-closed: if we can't check status, deny access
      return false;
    }
  }
}
