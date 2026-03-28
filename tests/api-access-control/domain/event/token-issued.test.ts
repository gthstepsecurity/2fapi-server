// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { TokenIssued } from "../../../../src/api-access-control/domain/event/token-issued.js";

describe("TokenIssued", () => {
  it("captures all issuance details", () => {
    const event = new TokenIssued(
      "alice-payment-service",
      "payment-service",
      "standard",
      "tok-001",
      1000000,
    );

    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.audience).toBe("payment-service");
    expect(event.authenticationLevel).toBe("standard");
    expect(event.tokenId).toBe("tok-001");
    expect(event.issuedAtMs).toBe(1000000);
  });

  it("has eventType 'TokenIssued'", () => {
    const event = new TokenIssued("client", "aud", "standard", "tok", 0);
    expect(event.eventType).toBe("TokenIssued");
  });

  it("records occurredAt timestamp", () => {
    const before = new Date();
    const event = new TokenIssued("client", "aud", "standard", "tok", 0);
    const after = new Date();

    expect(event.occurredAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(event.occurredAt.getTime()).toBeLessThanOrEqual(after.getTime());
  });

  it("does not leak sensitive data (no bearer token or secret in event)", () => {
    const event = new TokenIssued(
      "alice-payment-service",
      "payment-service",
      "standard",
      "tok-001",
      1000000,
    );

    // Verify the event only contains the expected fields
    const keys = Object.keys(event);
    expect(keys).not.toContain("bearerToken");
    expect(keys).not.toContain("signedBytes");
    expect(keys).not.toContain("secret");
    expect(keys).not.toContain("channelBindingHash");

    // Verify only expected fields are present
    expect(keys.sort()).toEqual([
      "audience",
      "authenticationLevel",
      "clientIdentifier",
      "eventType",
      "issuedAtMs",
      "occurredAt",
      "tokenId",
    ]);
  });
});
