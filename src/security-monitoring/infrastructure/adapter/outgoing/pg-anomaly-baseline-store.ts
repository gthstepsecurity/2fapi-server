// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyBaselineStore, ClientBaseline } from "../../../domain/port/outgoing/anomaly-baseline-store.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape returned from the anomaly_baselines table.
 */
interface BaselineRow {
  client_identifier: string;
  auths_per_hour: number;
}

/**
 * PostgreSQL implementation of AnomalyBaselineStore.
 *
 * Stores per-client authentication baselines for anomaly detection.
 * Uses UPSERT (INSERT ... ON CONFLICT) for atomic create/update.
 */
export class PgAnomalyBaselineStore implements AnomalyBaselineStore {
  constructor(private readonly db: DatabaseClient) {}

  async getBaseline(clientIdentifier: string): Promise<ClientBaseline | null> {
    const result = await this.db.query(
      "SELECT client_identifier, auths_per_hour FROM anomaly_baselines WHERE client_identifier = $1",
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0] as BaselineRow;
    return {
      clientIdentifier: row.client_identifier,
      authsPerHour: row.auths_per_hour,
    };
  }

  async saveBaseline(baseline: ClientBaseline): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `INSERT INTO anomaly_baselines (client_identifier, auths_per_hour, created_at, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (client_identifier)
       DO UPDATE SET
         auths_per_hour = EXCLUDED.auths_per_hour,
         updated_at = EXCLUDED.updated_at`,
      [baseline.clientIdentifier, baseline.authsPerHour, nowMs, nowMs],
    );
  }
}
