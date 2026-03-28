// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { SecretShare } from "../../../domain/model/secret-share.js";

export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * Server-side share storage port for distributed Sigma proofs (R31).
 */
export interface ServerShareStore {
  save(tenantId: string, clientId: string, shareS: Uint8Array, shareR: Uint8Array, partialCommitment: Uint8Array): Promise<void>;
  findByClient(tenantId: string, clientId: string): Promise<{ shareS: Uint8Array; shareR: Uint8Array } | null>;
  delete(tenantId: string, clientId: string): Promise<void>;
}

/**
 * PostgreSQL adapter for server secret share storage (R31).
 */
export class PgServerShareStore implements ServerShareStore {
  constructor(private readonly db: DatabaseClient) {}

  async save(
    tenantId: string, clientId: string,
    shareS: Uint8Array, shareR: Uint8Array, partialCommitment: Uint8Array,
  ): Promise<void> {
    await this.db.query(
      `INSERT INTO server_secret_shares (tenant_id, client_id, share_s, share_r, partial_commitment)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, client_id)
       DO UPDATE SET share_s = EXCLUDED.share_s, share_r = EXCLUDED.share_r,
         partial_commitment = EXCLUDED.partial_commitment, rotated_at = NOW()`,
      [tenantId, clientId, Buffer.from(shareS), Buffer.from(shareR), Buffer.from(partialCommitment)],
    );
  }

  async findByClient(tenantId: string, clientId: string): Promise<{ shareS: Uint8Array; shareR: Uint8Array } | null> {
    const result = await this.db.query(
      "SELECT share_s, share_r FROM server_secret_shares WHERE tenant_id = $1 AND client_id = $2",
      [tenantId, clientId],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0] as { share_s: Buffer; share_r: Buffer };
    return {
      shareS: new Uint8Array(row.share_s),
      shareR: new Uint8Array(row.share_r),
    };
  }

  async delete(tenantId: string, clientId: string): Promise<void> {
    await this.db.query(
      "DELETE FROM server_secret_shares WHERE tenant_id = $1 AND client_id = $2",
      [tenantId, clientId],
    );
  }
}
