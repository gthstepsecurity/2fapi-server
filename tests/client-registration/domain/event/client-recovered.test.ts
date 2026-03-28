// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ClientRecovered } from "../../../../src/client-registration/domain/event/client-recovered.js";

describe("ClientRecovered", () => {
  it("exposes eventType, clientIdentifier, recoveryMethod, and recoveredAtMs", () => {
    const event = new ClientRecovered("alice-payment-service", "phrase", 1700000000000);

    expect(event.eventType).toBe("ClientRecovered");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.recoveryMethod).toBe("phrase");
    expect(event.recoveredAtMs).toBe(1700000000000);
  });

  it("implements DomainEvent interface with occurredAt", () => {
    const event = new ClientRecovered("alice-payment-service", "phrase", 1700000000000);

    expect(event.eventType).toBeDefined();
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("accepts external_intervention as recovery method", () => {
    const event = new ClientRecovered("alice-payment-service", "external_intervention", 1700000000000);

    expect(event.recoveryMethod).toBe("external_intervention");
  });
});
