// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryAuditLogStore } from "../../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { AuditEntry } from "../../../../../src/security-monitoring/domain/model/audit-entry.js";
import { AuditEventType } from "../../../../../src/security-monitoring/domain/model/audit-event-type.js";

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

describe("InMemoryAuditLogStore", () => {
  it("appends and retrieves entries", async () => {
    const store = new InMemoryAuditLogStore();
    const entry = createTestEntry("e-1");
    await store.append(entry);

    const all = await store.findAll();
    expect(all.length).toBe(1);
    expect(all[0]!.id).toBe("e-1");
  });

  it("is append-only — entries accumulate", async () => {
    const store = new InMemoryAuditLogStore();
    await store.append(createTestEntry("e-1"));
    await store.append(createTestEntry("e-2"));
    await store.append(createTestEntry("e-3"));

    expect(await store.count()).toBe(3);
  });

  it("returns copies (not internal references)", async () => {
    const store = new InMemoryAuditLogStore();
    await store.append(createTestEntry("e-1"));

    const first = await store.findAll();
    const second = await store.findAll();
    expect(first).not.toBe(second); // different array instance
  });

  it("throws when unavailable", async () => {
    const store = new InMemoryAuditLogStore();
    store.setUnavailable(true);

    await expect(store.append(createTestEntry("e-1"))).rejects.toThrow("unavailable");
    await expect(store.findAll()).rejects.toThrow("unavailable");
  });

  it("handles 10K entries without data loss", async () => {
    const store = new InMemoryAuditLogStore();
    for (let i = 0; i < 10000; i++) {
      await store.append(createTestEntry(`e-${i}`, 1700000000000 + i));
    }
    expect(await store.count()).toBe(10000);
  });

  it("entries remain immutable after retrieval", async () => {
    const store = new InMemoryAuditLogStore();
    await store.append(createTestEntry("e-1"));

    const entries = await store.findAll();
    expect(Object.isFrozen(entries[0])).toBe(true);
  });
});
