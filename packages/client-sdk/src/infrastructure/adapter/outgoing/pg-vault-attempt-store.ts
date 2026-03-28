// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultAttemptStore } from "../../../domain/port/outgoing/vault-attempt-store.js";
import { VaultAttemptCounter } from "../../../domain/model/vault-attempt-counter.js";

export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

interface AttemptRow {
  client_id: string;
  device_id: string;
  consecutive_failures: number;
  is_wiped: boolean;
  threshold: number;
}

/**
 * PostgreSQL implementation of VaultAttemptStore.
 * Uses UPSERT for atomic create/update of attempt counters.
 */
export class PgVaultAttemptStore implements VaultAttemptStore {
  constructor(private readonly db: DatabaseClient) {}

  async findByDevice(clientId: string, deviceId: string): Promise<VaultAttemptCounter | null> {
    const result = await this.db.query(
      `SELECT client_id, device_id, consecutive_failures, is_wiped, threshold
       FROM vault_attempt_counters
       WHERE client_id = $1 AND device_id = $2`,
      [clientId, deviceId],
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0] as AttemptRow;
    return VaultAttemptCounter.restore(
      row.client_id,
      row.device_id,
      row.consecutive_failures,
      row.is_wiped,
      row.threshold,
    );
  }

  async save(counter: VaultAttemptCounter): Promise<void> {
    await this.db.query(
      `INSERT INTO vault_attempt_counters (client_id, device_id, consecutive_failures, is_wiped, threshold, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (client_id, device_id)
       DO UPDATE SET
         consecutive_failures = EXCLUDED.consecutive_failures,
         is_wiped = EXCLUDED.is_wiped,
         threshold = EXCLUDED.threshold,
         updated_at = NOW()`,
      [counter.clientId, counter.deviceId, counter.consecutiveFailures, counter.isWiped, counter.threshold],
    );
  }

  async delete(clientId: string, deviceId: string): Promise<void> {
    await this.db.query(
      "DELETE FROM vault_attempt_counters WHERE client_id = $1 AND device_id = $2",
      [clientId, deviceId],
    );
  }
}
