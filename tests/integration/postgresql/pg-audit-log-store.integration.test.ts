// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

/**
 * Integration tests for PgAuditLogStore against a real PostgreSQL instance.
 *
 * Prerequisites:
 *   docker compose up -d postgres
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("PgAuditLogStore [integration]", () => {
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id                  TEXT    NOT NULL,
        event_type          TEXT    NOT NULL,
        event_type_known    BOOLEAN NOT NULL DEFAULT TRUE,
        original_event_type TEXT,
        client_identifier   TEXT    NOT NULL,
        timestamp_ms        BIGINT  NOT NULL,
        source_address      TEXT    NOT NULL,
        details             JSONB   NOT NULL DEFAULT '{}',
        created_at          BIGINT  NOT NULL,
        updated_at          BIGINT  NOT NULL,
        CONSTRAINT pk_audit_log PRIMARY KEY (id)
      );
    `);

    const { PgAuditLogStore } = await import(
      "../../../src/security-monitoring/infrastructure/adapter/outgoing/pg-audit-log-store.js"
    );
    store = new PgAuditLogStore(pool);
  });

  afterAll(async () => {
    if (pool) {
      await pool.query("DROP TABLE IF EXISTS audit_log CASCADE");
      await pool.end();
    }
  });

  beforeEach(async () => {
    await pool.query("DELETE FROM audit_log");
  });

  it("should append and count entries", async () => {
    const { AuditEntry } = await import(
      "../../../src/security-monitoring/domain/model/audit-entry.js"
    );
    const { AuditEventType } = await import(
      "../../../src/security-monitoring/domain/model/audit-event-type.js"
    );

    const entry = AuditEntry.create({
      id: "audit-1",
      eventType: AuditEventType.from("enrollment_success"),
      clientIdentifier: "client-a",
      timestampMs: Date.now(),
      sourceAddress: "127.0.0.1",
      details: { action: "test" },
    });

    await store.append(entry);
    const count = await store.count();
    expect(count).toBe(1);
  });

  it("should findAll returns entries in timestamp order", async () => {
    const { AuditEntry } = await import(
      "../../../src/security-monitoring/domain/model/audit-entry.js"
    );
    const { AuditEventType } = await import(
      "../../../src/security-monitoring/domain/model/audit-event-type.js"
    );

    const entry1 = AuditEntry.create({
      id: "audit-first",
      eventType: AuditEventType.from("enrollment_success"),
      clientIdentifier: "client-a",
      timestampMs: 1000,
      sourceAddress: "127.0.0.1",
      details: {},
    });

    const entry2 = AuditEntry.create({
      id: "audit-second",
      eventType: AuditEventType.from("authentication_failure"),
      clientIdentifier: "client-b",
      timestampMs: 2000,
      sourceAddress: "192.168.1.1",
      details: { reason: "invalid_proof" },
    });

    await store.append(entry1);
    await store.append(entry2);

    const all = await store.findAll();
    expect(all).toHaveLength(2);
    expect(all[0]!.id).toBe("audit-first");
    expect(all[1]!.id).toBe("audit-second");
  });

  it("should preserve unknown event types", async () => {
    const { AuditEntry } = await import(
      "../../../src/security-monitoring/domain/model/audit-entry.js"
    );
    const { AuditEventType } = await import(
      "../../../src/security-monitoring/domain/model/audit-event-type.js"
    );

    const unknownType = AuditEventType.from("custom_event_xyz");
    const entry = AuditEntry.create({
      id: "audit-unknown",
      eventType: unknownType,
      clientIdentifier: "client-c",
      timestampMs: 3000,
      sourceAddress: "10.0.0.1",
      details: {},
    });

    await store.append(entry);
    const all = await store.findAll();
    expect(all).toHaveLength(1);
    expect(all[0]!.eventType.value).toBe("unknown_event");
    expect(all[0]!.eventType.originalValue).toBe("custom_event_xyz");
  });
});
