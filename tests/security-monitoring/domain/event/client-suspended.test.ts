// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ClientSuspended } from "../../../../src/security-monitoring/domain/event/client-suspended.js";

describe("ClientSuspended", () => {
  it("creates an integration event with all required fields", () => {
    const event = new ClientSuspended(
      "alice-payment-service",
      "concurrent_session",
      1700000000000,
      { ips: ["203.0.113.10", "198.51.100.42"] },
    );

    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.reason).toBe("concurrent_session");
    expect(event.detectedAtMs).toBe(1700000000000);
    expect(event.details).toEqual({ ips: ["203.0.113.10", "198.51.100.42"] });
    expect(event.eventType).toBe("ClientSuspended");
    expect(event.occurredAt).toEqual(new Date(1700000000000));
  });

  it("implements DomainEvent interface", () => {
    const event = new ClientSuspended("alice", "manual", 1000, {});

    expect(event.eventType).toBe("ClientSuspended");
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("supports all suspension reason values", () => {
    const reasons = [
      "concurrent_session",
      "geographic_impossibility",
      "volume_anomaly",
      "manual",
    ] as const;

    for (const reason of reasons) {
      const event = new ClientSuspended("alice", reason, 1000, {});
      expect(event.reason).toBe(reason);
    }
  });
});
