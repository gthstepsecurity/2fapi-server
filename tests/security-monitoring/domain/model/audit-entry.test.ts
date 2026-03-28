// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AuditEntry } from "../../../../src/security-monitoring/domain/model/audit-entry.js";
import { AuditEventType } from "../../../../src/security-monitoring/domain/model/audit-event-type.js";

describe("AuditEntry", () => {
  const TIMESTAMP = 1700000000000;

  function createEntry(overrides: Partial<{
    id: string;
    eventType: string;
    clientIdentifier: string;
    timestampMs: number;
    sourceAddress: string;
    details: Record<string, string>;
  }> = {}): AuditEntry {
    return AuditEntry.create({
      id: overrides.id ?? "entry-001",
      eventType: AuditEventType.from(overrides.eventType ?? "authentication_success"),
      clientIdentifier: overrides.clientIdentifier ?? "alice-payment-service",
      timestampMs: overrides.timestampMs ?? TIMESTAMP,
      sourceAddress: overrides.sourceAddress ?? "192.168.1.1",
      details: overrides.details ?? { challengeId: "ch-001" },
    });
  }

  it("creates with all required fields", () => {
    const entry = createEntry();
    expect(entry.id).toBe("entry-001");
    expect(entry.eventType.value).toBe("authentication_success");
    expect(entry.clientIdentifier).toBe("alice-payment-service");
    expect(entry.timestampMs).toBe(TIMESTAMP);
    expect(entry.sourceAddress).toBe("192.168.1.1");
    expect(entry.details).toEqual({ challengeId: "ch-001" });
  });

  it("does NOT include secrets in details", () => {
    const entry = createEntry({
      details: { reason: "invalid_proof" },
    });
    expect(entry.details).not.toHaveProperty("secret");
    expect(entry.details).not.toHaveProperty("blinding");
    expect(entry.details).not.toHaveProperty("proof");
  });

  it("rejects entry with secret field in details", () => {
    expect(() =>
      AuditEntry.create({
        id: "entry-bad",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: { secret: "should-not-be-here" },
      }),
    ).toThrow("Audit entry must not contain sensitive fields");
  });

  it("rejects entry with proof field in details", () => {
    expect(() =>
      AuditEntry.create({
        id: "entry-bad",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: { proof: "should-not-be-here" },
      }),
    ).toThrow("Audit entry must not contain sensitive fields");
  });

  it("rejects entry with blinding field in details", () => {
    expect(() =>
      AuditEntry.create({
        id: "entry-bad",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: { blinding: "should-not-be-here" },
      }),
    ).toThrow("Audit entry must not contain sensitive fields");
  });

  it("rejects entry with privateKey field in details", () => {
    expect(() =>
      AuditEntry.create({
        id: "entry-bad",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: { privateKey: "should-not-be-here" },
      }),
    ).toThrow("Audit entry must not contain sensitive fields");
  });

  it("rejects entry with blindingFactor field in details", () => {
    expect(() =>
      AuditEntry.create({
        id: "entry-bad",
        eventType: AuditEventType.from("authentication_failure"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: { blindingFactor: "should-not-be-here" },
      }),
    ).toThrow("Audit entry must not contain sensitive fields");
  });

  it("is immutable — properties are readonly", () => {
    const entry = createEntry();
    // TypeScript enforces readonly at compile time.
    // At runtime, we verify the object is frozen.
    expect(Object.isFrozen(entry)).toBe(true);
  });

  it("details object is also frozen", () => {
    const entry = createEntry({ details: { reason: "test" } });
    expect(Object.isFrozen(entry.details)).toBe(true);
  });

  it("rejects empty id", () => {
    expect(() =>
      AuditEntry.create({
        id: "",
        eventType: AuditEventType.from("authentication_success"),
        clientIdentifier: "alice",
        timestampMs: TIMESTAMP,
        sourceAddress: "10.0.0.1",
        details: {},
      }),
    ).toThrow("Audit entry ID must not be empty");
  });
});
