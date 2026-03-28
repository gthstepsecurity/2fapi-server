// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChallengeInvalidated } from "../../../../src/authentication-challenge/domain/event/challenge-invalidated.js";

describe("ChallengeInvalidated", () => {
  it("should contain client identifier and challenge reference", () => {
    const event = new ChallengeInvalidated("alice-payment-service", "ch-old-001");

    expect(event.eventType).toBe("ChallengeInvalidated");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.challengeReference).toBe("ch-old-001");
    expect(event.occurredAt).toBeInstanceOf(Date);
  });
});
