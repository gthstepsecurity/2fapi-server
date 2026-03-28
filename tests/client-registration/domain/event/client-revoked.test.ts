// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ClientRevoked } from "../../../../src/client-registration/domain/event/client-revoked.js";

describe("ClientRevoked", () => {
  it("exposes eventType, clientIdentifier, adminIdentity, and occurredAt", () => {
    const event = new ClientRevoked("client-1", "admin-alice");

    expect(event.eventType).toBe("ClientRevoked");
    expect(event.clientIdentifier).toBe("client-1");
    expect(event.adminIdentity).toBe("admin-alice");
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("implements DomainEvent interface", () => {
    const event = new ClientRevoked("client-1", "admin-alice");

    expect(event.eventType).toBeDefined();
    expect(event.occurredAt).toBeDefined();
  });
});
