// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

/**
 * Integration tests for PgClientRepository against a real PostgreSQL instance.
 *
 * Prerequisites:
 *   docker compose up -d postgres
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("PgClientRepository [integration]", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let pool: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let repository: any;

  beforeAll(async () => {
    // Dynamic import to avoid requiring pg in unit test runs
    const pg = await import("pg");
    pool = new pg.Pool({
      host: "localhost",
      port: 5432,
      database: "twofapi",
      user: "twofapi",
      password: "dev-password",
    });

    // Run migration
    await pool.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id              BYTEA       NOT NULL,
        identifier      TEXT        NOT NULL,
        commitment      BYTEA       NOT NULL,
        status          TEXT        NOT NULL DEFAULT 'active',
        created_at      BIGINT      NOT NULL,
        updated_at      BIGINT      NOT NULL,
        CONSTRAINT pk_clients PRIMARY KEY (identifier),
        CONSTRAINT uq_clients_id UNIQUE (id)
      );
    `);

    const { PgClientRepository } = await import(
      "../../../src/client-registration/infrastructure/adapter/outgoing/pg-client-repository.js"
    );
    repository = new PgClientRepository(pool);
  });

  afterAll(async () => {
    if (pool) {
      await pool.query("DROP TABLE IF EXISTS clients CASCADE");
      await pool.end();
    }
  });

  beforeEach(async () => {
    await pool.query("DELETE FROM clients");
  });

  it("should save and retrieve a client by identifier", async () => {
    const { Client } = await import(
      "../../../src/client-registration/domain/model/client.js"
    );
    const { ClientId } = await import(
      "../../../src/client-registration/domain/model/client-id.js"
    );
    const { Commitment } = await import(
      "../../../src/client-registration/domain/model/commitment.js"
    );

    const id = ClientId.fromBytes(new Uint8Array(16).fill(1));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0x42));
    const client = Client.register(id, "test-client", commitment);

    await repository.save(client);
    const found = await repository.findByIdentifier("test-client");

    expect(found).not.toBeNull();
    expect(found!.identifier).toBe("test-client");
    expect(found!.status).toBe("active");
  });

  it("should return null for a non-existent identifier", async () => {
    const found = await repository.findByIdentifier("non-existent");
    expect(found).toBeNull();
  });

  it("should update a client status", async () => {
    const { Client } = await import(
      "../../../src/client-registration/domain/model/client.js"
    );
    const { ClientId } = await import(
      "../../../src/client-registration/domain/model/client-id.js"
    );
    const { Commitment } = await import(
      "../../../src/client-registration/domain/model/commitment.js"
    );

    const id = ClientId.fromBytes(new Uint8Array(16).fill(2));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0x43));
    const client = Client.register(id, "update-test", commitment);

    await repository.save(client);
    const revoked = client.revoke();
    await repository.update(revoked);

    const found = await repository.findByIdentifier("update-test");
    expect(found!.status).toBe("revoked");
  });

  it("should check existence by identifier", async () => {
    const { Client } = await import(
      "../../../src/client-registration/domain/model/client.js"
    );
    const { ClientId } = await import(
      "../../../src/client-registration/domain/model/client-id.js"
    );
    const { Commitment } = await import(
      "../../../src/client-registration/domain/model/commitment.js"
    );

    const id = ClientId.fromBytes(new Uint8Array(16).fill(3));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0x44));
    const client = Client.register(id, "exists-test", commitment);

    expect(await repository.existsByIdentifier("exists-test")).toBe(false);
    await repository.save(client);
    expect(await repository.existsByIdentifier("exists-test")).toBe(true);
  });
});
