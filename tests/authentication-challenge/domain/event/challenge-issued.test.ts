// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChallengeIssued } from "../../../../src/authentication-challenge/domain/event/challenge-issued.js";

describe("ChallengeIssued", () => {
  it("should contain client identifier, challenge reference, and expiry timestamp", () => {
    const event = new ChallengeIssued("alice-payment-service", "ch-001", 1000120000);

    expect(event.eventType).toBe("ChallengeIssued");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.challengeReference).toBe("ch-001");
    expect(event.expiresAtMs).toBe(1000120000);
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("should never expose the nonce value", () => {
    const event = new ChallengeIssued("alice", "ch-002", 1000000);

    expect(event).not.toHaveProperty("nonce");
    expect(event).not.toHaveProperty("credential");
  });
});
