// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RecoveryHashStore } from "../../../domain/port/outgoing/recovery-hash-store.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * Row shape returned from the recovery_hashes table.
 */
interface RecoveryHashRow {
  client_identifier: string;
  hash: Buffer;
  salt: Buffer;
  failed_attempts: number;
}

/**
 * PostgreSQL implementation of RecoveryHashStore.
 *
 * Maps between the RecoveryHashStore domain port and the `recovery_hashes` table.
 * Uses UPSERT (INSERT ... ON CONFLICT) for store operations to handle
 * both creation and update atomically.
 *
 * The salt column is stored but not used by the domain port interface
 * (the Argon2 hash itself contains the salt). It is preserved for
 * auditing and potential future key derivation changes.
 */
export class PgRecoveryHashStore implements RecoveryHashStore {
  constructor(private readonly db: DatabaseClient) {}

  async storeHash(clientIdentifier: string, hash: Uint8Array): Promise<void> {
    const nowMs = Date.now();
    // Extract salt from the hash if present, otherwise store empty salt.
    // The Argon2 encoded hash contains the salt internally.
    const emptyBuf = Buffer.alloc(0);

    await this.db.query(
      `INSERT INTO recovery_hashes (client_identifier, hash, salt, failed_attempts, created_at, updated_at)
       VALUES ($1, $2, $3, 0, $4, $5)
       ON CONFLICT (client_identifier)
       DO UPDATE SET
         hash = EXCLUDED.hash,
         salt = EXCLUDED.salt,
         failed_attempts = 0,
         updated_at = EXCLUDED.updated_at`,
      [clientIdentifier, Buffer.from(hash), emptyBuf, nowMs, nowMs],
    );
  }

  async getHash(clientIdentifier: string): Promise<Uint8Array | null> {
    const result = await this.db.query(
      "SELECT hash FROM recovery_hashes WHERE client_identifier = $1",
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0] as RecoveryHashRow;
    return new Uint8Array(row.hash);
  }

  async recordFailedAttempt(clientIdentifier: string): Promise<number> {
    const nowMs = Date.now();
    const result = await this.db.query(
      `UPDATE recovery_hashes
       SET failed_attempts = failed_attempts + 1, updated_at = $1
       WHERE client_identifier = $2
       RETURNING failed_attempts`,
      [nowMs, clientIdentifier],
    );

    if (result.rows.length === 0) {
      // No hash stored for this client; return 1 as if first attempt
      return 1;
    }

    return (result.rows[0] as RecoveryHashRow).failed_attempts;
  }

  async resetAttempts(clientIdentifier: string): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `UPDATE recovery_hashes
       SET failed_attempts = 0, updated_at = $1
       WHERE client_identifier = $2`,
      [nowMs, clientIdentifier],
    );
  }

  async getAttemptCount(clientIdentifier: string): Promise<number> {
    const result = await this.db.query(
      "SELECT failed_attempts FROM recovery_hashes WHERE client_identifier = $1",
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return 0;
    }

    return (result.rows[0] as RecoveryHashRow).failed_attempts;
  }

  async deleteHash(clientIdentifier: string): Promise<void> {
    await this.db.query(
      "DELETE FROM recovery_hashes WHERE client_identifier = $1",
      [clientIdentifier],
    );
  }
}
