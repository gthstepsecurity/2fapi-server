// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentLookup, CommitmentInfo } from "../../../domain/port/outgoing/commitment-lookup.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape from the clients table (subset for commitment lookup).
 */
interface ClientRow {
  commitment: Buffer;
  status: string;
}

/**
 * PostgreSQL-backed commitment lookup for the ZK Verification context.
 *
 * Cross-context bridge: queries the clients table (owned by Client Registration)
 * to retrieve a client's stored Pedersen commitment and status for proof verification.
 */
export class PgCommitmentLookup implements CommitmentLookup {
  constructor(private readonly db: DatabaseClient) {}

  async findByClientIdentifier(clientIdentifier: string): Promise<CommitmentInfo | null> {
    try {
      const result = await this.db.query(
        "SELECT commitment, status FROM clients WHERE identifier = $1",
        [clientIdentifier],
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0] as ClientRow;
      const knownStatuses = new Set(["active", "revoked"]);
      const clientStatus: "active" | "revoked" | "unknown" = knownStatuses.has(row.status)
        ? (row.status as "active" | "revoked")
        : "unknown";

      return {
        commitment: new Uint8Array(row.commitment),
        clientStatus,
      };
    } catch {
      // Database errors are treated as "not found" (fail-closed for verification)
      return null;
    }
  }
}
