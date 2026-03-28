// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AuditEventType, KNOWN_AUDIT_EVENT_TYPES } from "../../../../src/security-monitoring/domain/model/audit-event-type.js";

describe("AuditEventType", () => {
  it("creates a known event type", () => {
    const type = AuditEventType.from("enrollment_success");
    expect(type.value).toBe("enrollment_success");
    expect(type.isKnown).toBe(true);
  });

  it("creates an unknown event type", () => {
    const type = AuditEventType.from("some_random_event");
    expect(type.value).toBe("unknown_event");
    expect(type.isKnown).toBe(false);
    expect(type.originalValue).toBe("some_random_event");
  });

  it("recognizes all known event types", () => {
    for (const knownType of KNOWN_AUDIT_EVENT_TYPES) {
      const type = AuditEventType.from(knownType);
      expect(type.isKnown).toBe(true);
      expect(type.value).toBe(knownType);
    }
  });

  it("rejects empty string", () => {
    expect(() => AuditEventType.from("")).toThrow("Event type must not be empty");
  });

  it("equals another AuditEventType with same value", () => {
    const a = AuditEventType.from("authentication_failure");
    const b = AuditEventType.from("authentication_failure");
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal a different known AuditEventType", () => {
    // Kill mutant: `return true` instead of checking values
    const a = AuditEventType.from("authentication_failure");
    const b = AuditEventType.from("authentication_success");
    expect(a.equals(b)).toBe(false);
  });

  it("equals requires both value AND originalValue to match", () => {
    // Kill mutant: `return this.value === other.value || this.originalValue === other.originalValue`
    // and: `return true && this.originalValue === other.originalValue`
    // and: `return this.value === other.value && true`
    // Two unknown events with different original values should NOT be equal
    // even though both have value = "unknown_event"
    const a = AuditEventType.from("custom_event_a");
    const b = AuditEventType.from("custom_event_b");
    expect(a.value).toBe("unknown_event");
    expect(b.value).toBe("unknown_event");
    // Same value but different originalValue → NOT equal
    expect(a.equals(b)).toBe(false);
  });

  it("known and unknown events are not equal even if value matches by coincidence", () => {
    // Kill mutant: `return true && this.originalValue === other.originalValue`
    const known = AuditEventType.from("authentication_failure");
    const unknown = AuditEventType.from("some_custom");
    // Different values → not equal
    expect(known.equals(unknown)).toBe(false);
  });
});
