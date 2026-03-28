// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeRepository } from "../../../domain/port/outgoing/challenge-repository.js";
import { Challenge } from "../../../domain/model/challenge.js";
import { ChallengeId } from "../../../domain/model/challenge-id.js";
import { Nonce } from "../../../domain/model/nonce.js";
import { ChannelBinding } from "../../../domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../../domain/model/challenge-expiry.js";
import type { FirstFactorType } from "../../../domain/model/first-factor-type.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }>;
}

/**
 * Row shape returned from the challenges table.
 */
interface ChallengeRow {
  id: string;
  client_identifier: string;
  nonce: Buffer;
  channel_binding: Buffer;
  issued_at_ms: string;
  ttl_ms: string;
  first_factor_type: string;
  status: string;
}

/**
 * Maximum number of challenges before capacity is considered 100%.
 * This value is configurable via constructor.
 */
const DEFAULT_MAX_CAPACITY = 100_000;

/**
 * PostgreSQL implementation of ChallengeRepository.
 *
 * Maps between the Challenge domain model and the `challenges` table.
 * Nonce bytes include both the random part and the counter suffix.
 */
export class PgChallengeRepository implements ChallengeRepository {
  constructor(
    private readonly db: DatabaseClient,
    private readonly maxCapacity: number = DEFAULT_MAX_CAPACITY,
  ) {}

  async save(challenge: Challenge): Promise<void> {
    const nowMs = Date.now();
    await this.db.query(
      `INSERT INTO challenges
       (id, client_identifier, nonce, channel_binding, issued_at_ms, ttl_ms, first_factor_type, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        challenge.id.value,
        challenge.clientIdentifier,
        Buffer.from(challenge.nonce.toBytes()),
        Buffer.from(challenge.channelBinding.toBytes()),
        challenge.expiry.issuedAtMs,
        challenge.expiry.ttlMs,
        challenge.firstFactorType,
        challenge.status,
        nowMs,
        nowMs,
      ],
    );
  }

  async findById(id: ChallengeId): Promise<Challenge | null> {
    const result = await this.db.query(
      `SELECT id, client_identifier, nonce, channel_binding, issued_at_ms, ttl_ms, first_factor_type, status
       FROM challenges WHERE id = $1`,
      [id.value],
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.toDomain(result.rows[0] as ChallengeRow);
  }

  async findPendingByClientIdentifier(clientIdentifier: string): Promise<Challenge | null> {
    const result = await this.db.query(
      `SELECT id, client_identifier, nonce, channel_binding, issued_at_ms, ttl_ms, first_factor_type, status
       FROM challenges
       WHERE client_identifier = $1 AND status = 'pending'
       ORDER BY issued_at_ms DESC
       LIMIT 1`,
      [clientIdentifier],
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.toDomain(result.rows[0] as ChallengeRow);
  }

  async delete(id: ChallengeId): Promise<void> {
    await this.db.query("DELETE FROM challenges WHERE id = $1", [id.value]);
  }

  async deleteExpiredBefore(nowMs: number): Promise<number> {
    const result = await this.db.query(
      `DELETE FROM challenges
       WHERE status != 'used'
         AND (issued_at_ms + ttl_ms) <= $1`,
      [nowMs],
    );
    return result.rowCount ?? 0;
  }

  async capacityPercentage(): Promise<number> {
    const result = await this.db.query("SELECT COUNT(*) AS cnt FROM challenges");
    const count = Number((result.rows[0] as { cnt: string }).cnt);
    return Math.round((count / this.maxCapacity) * 100);
  }

  /**
   * Reconstructs a Challenge domain object from a database row.
   *
   * Because the Challenge constructor is private and only accessible via
   * Challenge.issue(), and because we may have used/invalidated challenges
   * in the DB, we use issue() then transition to the correct status.
   */
  private toDomain(row: ChallengeRow): Challenge {
    const id = ChallengeId.fromString(row.id);
    const nonceBytes = new Uint8Array(row.nonce);
    // The nonce stores random_part || counter. We need to split them.
    // Counter is the last 8 bytes (BigUint64 big-endian).
    const COUNTER_SIZE = 8;
    const randomPart = nonceBytes.slice(0, nonceBytes.length - COUNTER_SIZE);
    const counterView = new DataView(nonceBytes.buffer, nonceBytes.byteOffset + nonceBytes.length - COUNTER_SIZE, COUNTER_SIZE);
    const counter = counterView.getBigUint64(0, false);
    const nonce = Nonce.create(randomPart, counter);

    const channelBinding = ChannelBinding.fromTlsExporter(new Uint8Array(row.channel_binding));
    const expiry = ChallengeExpiry.create(Number(row.issued_at_ms), Number(row.ttl_ms));
    const firstFactorType = row.first_factor_type as FirstFactorType;

    let challenge = Challenge.issue(id, row.client_identifier, nonce, channelBinding, expiry, firstFactorType);

    if (row.status === "used") {
      challenge = challenge.markUsed();
    } else if (row.status === "invalidated") {
      challenge = challenge.invalidate();
    }

    return challenge;
  }
}
