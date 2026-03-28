// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ClientReactivated } from "../../../../src/client-registration/domain/event/client-reactivated.js";

describe("ClientReactivated", () => {
  it("exposes eventType, clientIdentifier, adminIdentity, and reactivatedAtMs", () => {
    const event = new ClientReactivated("alice-payment-service", "bob-admin-id", 1700000000000);

    expect(event.eventType).toBe("ClientReactivated");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.adminIdentity).toBe("bob-admin-id");
    expect(event.reactivatedAtMs).toBe(1700000000000);
  });

  it("implements DomainEvent interface with occurredAt", () => {
    const event = new ClientReactivated("alice-payment-service", "bob-admin-id", 1700000000000);

    expect(event.eventType).toBeDefined();
    expect(event.occurredAt).toBeInstanceOf(Date);
  });
});
