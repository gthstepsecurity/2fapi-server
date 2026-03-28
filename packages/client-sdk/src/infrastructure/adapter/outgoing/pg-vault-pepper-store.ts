// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultPepperStore } from "../../../domain/port/outgoing/vault-pepper-store.js";
import { VaultPepper } from "../../../domain/model/vault-pepper.js";

/**
 * Minimal database client interface (subset of pg.Pool).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

interface PepperRow {
  client_id: string;
  device_id: string;
  pepper: Buffer;
}

/**
 * PostgreSQL implementation of VaultPepperStore.
 * Stores vault peppers server-side per (client_id, device_id).
 */
export class PgVaultPepperStore implements VaultPepperStore {
  constructor(private readonly db: DatabaseClient) {}

  async save(pepper: VaultPepper): Promise<void> {
    await this.db.query(
      `INSERT INTO vault_peppers (client_id, device_id, pepper)
       VALUES ($1, $2, $3)
       ON CONFLICT (client_id, device_id)
       DO UPDATE SET pepper = EXCLUDED.pepper, created_at = NOW()`,
      [pepper.clientId, pepper.deviceId, Buffer.from(pepper.value)],
    );
  }

  async findByDevice(clientId: string, deviceId: string): Promise<VaultPepper | null> {
    const result = await this.db.query(
      "SELECT client_id, device_id, pepper FROM vault_peppers WHERE client_id = $1 AND device_id = $2",
      [clientId, deviceId],
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0] as PepperRow;
    return VaultPepper.restore(
      row.client_id,
      row.device_id,
      new Uint8Array(row.pepper),
      false,
    );
  }

  async delete(clientId: string, deviceId: string): Promise<void> {
    await this.db.query(
      "DELETE FROM vault_peppers WHERE client_id = $1 AND device_id = $2",
      [clientId, deviceId],
    );
  }
}
