// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientRepository } from "../../../domain/port/outgoing/client-repository.js";
import { Client } from "../../../domain/model/client.js";
import { ClientId } from "../../../domain/model/client-id.js";
import { Commitment } from "../../../domain/model/commitment.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * Row shape returned from the clients table.
 */
interface ClientRow {
  id: Buffer;
  identifier: string;
  commitment: Buffer;
  status: string;
  commitment_version: number;
  created_at: string;
  updated_at: string;
}

/**
 * PostgreSQL implementation of ClientRepository.
 *
 * Maps between the Client domain model and the `clients` table.
 * Uses BYTEA for cryptographic material and TEXT for identifiers.
 */
export class PgClientRepository implements ClientRepository {
  constructor(private readonly db: DatabaseClient) {}

  async save(client: Client): Promise<void> {
    const nowMs = Date.now();
    const result = await this.db.query(
      `INSERT INTO clients (id, identifier, commitment, status, commitment_version, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        Buffer.from(client.id.toBytes()),
        client.identifier,
        Buffer.from(client.commitment.toBytes()),
        client.status,
        client.commitmentVersion,
        nowMs,
        nowMs,
      ],
    );

    if (result.rowCount === 0) {
      throw new Error("Optimistic concurrency conflict");
    }
  }

  async update(client: Client): Promise<void> {
    const nowMs = Date.now();
    const result = await this.db.query(
      `UPDATE clients
       SET commitment = $1, status = $2, commitment_version = $3, updated_at = $4
       WHERE identifier = $5`,
      [
        Buffer.from(client.commitment.toBytes()),
        client.status,
        client.commitmentVersion,
        nowMs,
        client.identifier,
      ],
    );

    if (result.rowCount === 0) {
      throw new Error("Client not found for update");
    }
  }

  async findByIdentifier(identifier: string): Promise<Client | null> {
    const result = await this.db.query(
      "SELECT id, identifier, commitment, status, commitment_version FROM clients WHERE identifier = $1",
      [identifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.toDomain(result.rows[0] as ClientRow);
  }

  async existsByIdentifier(identifier: string): Promise<boolean> {
    const result = await this.db.query(
      "SELECT 1 FROM clients WHERE identifier = $1 LIMIT 1",
      [identifier],
    );
    return result.rows.length > 0;
  }

  /**
   * Maps a database row to the Client domain model.
   */
  private toDomain(row: ClientRow): Client {
    const id = ClientId.fromBytes(new Uint8Array(row.id));
    const commitment = Commitment.fromBytes(new Uint8Array(row.commitment));
    const knownStatuses = new Set(["active", "suspended", "revoked"]);
    const status: "active" | "suspended" | "revoked" = knownStatuses.has(row.status)
      ? (row.status as "active" | "suspended" | "revoked")
      : "suspended";
    const commitmentVersion = row.commitment_version ?? 1;

    return Client.reconstitute(id, row.identifier, commitment, status, commitmentVersion);
  }
}
