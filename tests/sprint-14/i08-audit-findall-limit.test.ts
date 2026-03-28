// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryAuditLogStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { AuditEntry } from "../../src/security-monitoring/domain/model/audit-entry.js";
import { AuditEventType } from "../../src/security-monitoring/domain/model/audit-event-type.js";

function createTestEntry(id: string, timestampMs = 1700000000000): AuditEntry {
  return AuditEntry.create({
    id,
    eventType: AuditEventType.from("authentication_success"),
    clientIdentifier: "alice",
    timestampMs,
    sourceAddress: "10.0.0.1",
    details: {},
  });
}

describe("I-08: Audit findAll has mandatory LIMIT", () => {
  it("findAll with default limit returns at most 1000 entries", async () => {
    const store = new InMemoryAuditLogStore();
    for (let i = 0; i < 1100; i++) {
      await store.append(createTestEntry(`e-${i}`, 1700000000000 + i));
    }

    const entries = await store.findAll();
    expect(entries.length).toBeLessThanOrEqual(1000);
  });

  it("findAll with custom limit returns at most that many entries", async () => {
    const store = new InMemoryAuditLogStore();
    for (let i = 0; i < 50; i++) {
      await store.append(createTestEntry(`e-${i}`, 1700000000000 + i));
    }

    const entries = await store.findAll({ limit: 10 });
    expect(entries.length).toBe(10);
  });

  it("findAll with offset skips entries", async () => {
    const store = new InMemoryAuditLogStore();
    for (let i = 0; i < 20; i++) {
      await store.append(createTestEntry(`e-${i}`, 1700000000000 + i));
    }

    const entries = await store.findAll({ limit: 5, offset: 10 });
    expect(entries.length).toBe(5);
    expect(entries[0]!.id).toBe("e-10");
  });

  it("findAll returns fewer entries when offset + limit exceeds total", async () => {
    const store = new InMemoryAuditLogStore();
    for (let i = 0; i < 5; i++) {
      await store.append(createTestEntry(`e-${i}`, 1700000000000 + i));
    }

    const entries = await store.findAll({ limit: 10, offset: 3 });
    expect(entries.length).toBe(2);
  });
});
