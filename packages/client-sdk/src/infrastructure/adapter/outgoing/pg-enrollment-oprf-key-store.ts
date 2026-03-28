// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { EnrollmentOprfKeyStore } from "../../../domain/port/outgoing/enrollment-oprf-key-store.js";

export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * PostgreSQL adapter for enrollment OPRF key storage (R15-02).
 * Per-user keys — limits blast radius of a breach to a single user.
 */
export class PgEnrollmentOprfKeyStore implements EnrollmentOprfKeyStore {
  constructor(private readonly db: DatabaseClient) {}

  async generate(tenantId: string, clientId: string): Promise<void> {
    const { randomBytes } = await import("node:crypto");
    const key = randomBytes(32);
    await this.db.query(
      `INSERT INTO enrollment_oprf_keys (tenant_id, client_id, oprf_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (tenant_id, client_id)
       DO UPDATE SET oprf_key = EXCLUDED.oprf_key, rotated_at = NOW()`,
      [tenantId, clientId, key],
    );
  }

  async exists(tenantId: string, clientId: string): Promise<boolean> {
    const result = await this.db.query(
      "SELECT 1 FROM enrollment_oprf_keys WHERE tenant_id = $1 AND client_id = $2",
      [tenantId, clientId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async evaluate(tenantId: string, clientId: string, blindedPoint: Uint8Array): Promise<Uint8Array> {
    const result = await this.db.query(
      "SELECT oprf_key FROM enrollment_oprf_keys WHERE tenant_id = $1 AND client_id = $2",
      [tenantId, clientId],
    );
    if (result.rows.length === 0) {
      throw new Error("No enrollment OPRF key found for this user");
    }
    const row = result.rows[0] as { oprf_key: Buffer };
    // In production: this evaluation happens INSIDE the HSM, not in application code.
    // The key is extracted here only for non-HSM deployments.
    // TODO: wire to NapiOprfEvaluator for real Ristretto scalar multiplication
    return new Uint8Array(row.oprf_key);
  }

  async delete(tenantId: string, clientId: string): Promise<void> {
    await this.db.query(
      "DELETE FROM enrollment_oprf_keys WHERE tenant_id = $1 AND client_id = $2",
      [tenantId, clientId],
    );
  }
}
