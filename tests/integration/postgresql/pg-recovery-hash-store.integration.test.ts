// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

/**
 * Integration tests for PgRecoveryHashStore against a real PostgreSQL instance.
 *
 * Prerequisites:
 *   docker compose up -d postgres
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("PgRecoveryHashStore [integration]", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let pool: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let store: any;

  beforeAll(async () => {
    const pg = await import("pg");
    pool = new pg.Pool({
      host: "localhost",
      port: 5432,
      database: "twofapi",
      user: "twofapi",
      password: "dev-password",
    });

    // Ensure clients table exists (FK target)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id              BYTEA       NOT NULL,
        identifier      TEXT        NOT NULL,
        commitment      BYTEA       NOT NULL,
        status          TEXT        NOT NULL DEFAULT 'active',
        commitment_version INTEGER  NOT NULL DEFAULT 1,
        created_at      BIGINT      NOT NULL,
        updated_at      BIGINT      NOT NULL,
        CONSTRAINT pk_clients PRIMARY KEY (identifier),
        CONSTRAINT uq_clients_id UNIQUE (id)
      );
    `);

    // Ensure recovery_hashes table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS recovery_hashes (
        client_identifier   TEXT        PRIMARY KEY,
        hash                BYTEA       NOT NULL,
        salt                BYTEA       NOT NULL,
        failed_attempts     INTEGER     NOT NULL DEFAULT 0,
        created_at          BIGINT      NOT NULL,
        updated_at          BIGINT      NOT NULL,
        CONSTRAINT fk_recovery_client FOREIGN KEY (client_identifier)
            REFERENCES clients(identifier)
      );
    `);

    // Insert a test client for FK constraints
    await pool.query(
      `INSERT INTO clients (id, identifier, commitment, status, commitment_version, created_at, updated_at)
       VALUES ($1, $2, $3, 'active', 1, $4, $5)
       ON CONFLICT (identifier) DO NOTHING`,
      [Buffer.alloc(16, 0xaa), "test-client", Buffer.alloc(32, 0xbb), Date.now(), Date.now()],
    );

    const { PgRecoveryHashStore } = await import(
      "../../../src/client-registration/infrastructure/adapter/outgoing/pg-recovery-hash-store.js"
    );
    store = new PgRecoveryHashStore(pool);
  });

  afterAll(async () => {
    if (pool) {
      await pool.query("DELETE FROM recovery_hashes");
      await pool.end();
    }
  });

  beforeEach(async () => {
    await pool.query("DELETE FROM recovery_hashes");
  });

  it("should store and retrieve a hash", async () => {
    const hash = new Uint8Array(32).fill(0x42);
    await store.storeHash("test-client", hash);

    const retrieved = await store.getHash("test-client");
    expect(retrieved).not.toBeNull();
    expect(retrieved).toEqual(hash);
  });

  it("should return null for non-existent client", async () => {
    const retrieved = await store.getHash("non-existent");
    expect(retrieved).toBeNull();
  });

  it("should track failed attempts", async () => {
    const hash = new Uint8Array(32).fill(0x42);
    await store.storeHash("test-client", hash);

    const count1 = await store.recordFailedAttempt("test-client");
    expect(count1).toBe(1);

    const count2 = await store.recordFailedAttempt("test-client");
    expect(count2).toBe(2);

    const currentCount = await store.getAttemptCount("test-client");
    expect(currentCount).toBe(2);
  });

  it("should reset attempts", async () => {
    const hash = new Uint8Array(32).fill(0x42);
    await store.storeHash("test-client", hash);

    await store.recordFailedAttempt("test-client");
    await store.recordFailedAttempt("test-client");
    await store.resetAttempts("test-client");

    const count = await store.getAttemptCount("test-client");
    expect(count).toBe(0);
  });

  it("should delete hash and reset attempts", async () => {
    const hash = new Uint8Array(32).fill(0x42);
    await store.storeHash("test-client", hash);
    await store.recordFailedAttempt("test-client");

    await store.deleteHash("test-client");

    const retrieved = await store.getHash("test-client");
    expect(retrieved).toBeNull();
    const count = await store.getAttemptCount("test-client");
    expect(count).toBe(0);
  });

  it("should overwrite hash on re-store", async () => {
    const hash1 = new Uint8Array(32).fill(0x42);
    const hash2 = new Uint8Array(32).fill(0x99);

    await store.storeHash("test-client", hash1);
    await store.recordFailedAttempt("test-client");

    await store.storeHash("test-client", hash2);

    const retrieved = await store.getHash("test-client");
    expect(retrieved).toEqual(hash2);

    // Failed attempts should be reset on re-store
    const count = await store.getAttemptCount("test-client");
    expect(count).toBe(0);
  });
});
