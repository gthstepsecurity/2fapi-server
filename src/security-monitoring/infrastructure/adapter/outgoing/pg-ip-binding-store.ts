// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { IpBindingStore } from "../../../domain/port/outgoing/ip-binding-store.js";
import { IpBinding } from "../../../domain/model/ip-binding.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape returned from the ip_bindings table.
 */
interface IpBindingRow {
  id: string;
  client_identifier: string;
  source_ip: string;
  bound_at_ms: string;
}

/**
 * PostgreSQL implementation of IpBindingStore.
 *
 * Maps between the IpBinding domain model and the `ip_bindings` table.
 * Stores one row per IP binding event (append-only for audit trail).
 */
export class PgIpBindingStore implements IpBindingStore {
  constructor(private readonly db: DatabaseClient) {}

  async save(binding: IpBinding): Promise<void> {
    const id = `${binding.clientIdentifier}:${binding.sourceIp}:${binding.boundAtMs}`;
    await this.db.query(
      `INSERT INTO ip_bindings (id, client_identifier, source_ip, bound_at_ms)
       VALUES ($1, $2, $3, $4)`,
      [id, binding.clientIdentifier, binding.sourceIp, binding.boundAtMs],
    );
  }

  async findByClientIdentifier(clientIdentifier: string): Promise<readonly IpBinding[]> {
    const result = await this.db.query(
      `SELECT id, client_identifier, source_ip, bound_at_ms
       FROM ip_bindings
       WHERE client_identifier = $1
       ORDER BY bound_at_ms ASC`,
      [clientIdentifier],
    );

    return result.rows.map((row) => this.toDomain(row as IpBindingRow));
  }

  async findLatestByClientIdentifier(clientIdentifier: string): Promise<IpBinding | null> {
    const result = await this.db.query(
      `SELECT id, client_identifier, source_ip, bound_at_ms
       FROM ip_bindings
       WHERE client_identifier = $1
       ORDER BY bound_at_ms DESC
       LIMIT 1`,
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.toDomain(result.rows[0] as IpBindingRow);
  }

  private toDomain(row: IpBindingRow): IpBinding {
    return IpBinding.create(
      row.client_identifier,
      row.source_ip,
      Number(row.bound_at_ms),
    );
  }
}
