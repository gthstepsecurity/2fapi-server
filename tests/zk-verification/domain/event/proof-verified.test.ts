// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ProofVerified } from "../../../../src/zk-verification/domain/event/proof-verified.js";

describe("ProofVerified", () => {
  it("should contain client identifier, challenge id, and verification timestamp", () => {
    const verifiedAt = new Date(1000120000);
    const event = new ProofVerified("alice-payment-service", "ch-001", 1000120000, verifiedAt);

    expect(event.eventType).toBe("ProofVerified");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.challengeId).toBe("ch-001");
    expect(event.verifiedAtMs).toBe(1000120000);
    expect(event.occurredAt).toBeInstanceOf(Date);
    expect(event.occurredAt).toBe(verifiedAt);
  });

  it("should use injected timestamp instead of system clock", () => {
    const injectedDate = new Date("2025-06-15T10:00:00Z");
    const event = new ProofVerified("alice", "ch-003", 1718445600000, injectedDate);

    expect(event.occurredAt).toBe(injectedDate);
    expect(event.occurredAt.toISOString()).toBe("2025-06-15T10:00:00.000Z");
  });

  it("should never expose proof data or commitment", () => {
    const event = new ProofVerified("alice", "ch-002", 1000000, new Date(1000000));

    expect(event).not.toHaveProperty("proof");
    expect(event).not.toHaveProperty("commitment");
    expect(event).not.toHaveProperty("nonce");
  });
});
