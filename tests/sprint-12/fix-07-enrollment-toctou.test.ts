// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollClientUseCase } from "../../src/client-registration/application/usecase/enroll-client.usecase.js";
import { EnrollmentPolicy } from "../../src/client-registration/domain/service/enrollment-policy.js";
import type { ClientRepository } from "../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "../../src/client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import { Client } from "../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../src/client-registration/domain/model/commitment.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createNoopRateLimiter,
  validRequest,
} from "../helpers/enrollment-test-helpers.js";

function createStubCommitmentVerifier(): CommitmentVerifier {
  return {
    isCanonical: () => true,
    isValidGroupElement: () => true,
    isIdentityElement: () => false,
  };
}

function createStubProofVerifier(): ProofOfPossessionVerifier {
  return { verify: () => true };
}

function createStubIdGenerator() {
  let counter = 0;
  return {
    generate: () => {
      counter++;
      const bytes = new Uint8Array(16);
      bytes[0] = counter;
      return ClientId.fromBytes(bytes);
    },
  };
}

describe("FIX 7 — Enrollment TOCTOU Race Condition", () => {
  it("save conflict with same commitment triggers retry and returns idempotent success", async () => {
    // Simulate: findByIdentifier returns null (TOCTOU gap), save throws conflict,
    // retry findByIdentifier returns the client (saved by the other concurrent request).
    let saveCallCount = 0;
    let findCallCount = 0;

    // The "winning" client that was saved by the concurrent request
    const winningClient = Client.register(
      ClientId.fromBytes(new Uint8Array(16).fill(7)),
      "toctou-client",
      Commitment.fromBytes(new Uint8Array(32).fill(42)), // Same commitment
    );

    const repository: ClientRepository = {
      save: async () => {
        saveCallCount++;
        // Always throw concurrency conflict (simulating the losing request)
        throw new Error("Optimistic concurrency conflict: duplicate identifier");
      },
      update: async () => {},
      findByIdentifier: async (identifier: string) => {
        findCallCount++;
        if (findCallCount === 1) {
          // First call: client not found (TOCTOU gap — just checked, not yet saved by winner)
          return null;
        }
        // Second call (retry after conflict): winner has saved the client
        return winningClient;
      },
      existsByIdentifier: async () => false,
    };

    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest("toctou-client", 42));

    // The retry-on-conflict should detect the idempotent case and succeed
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.clientIdentifier).toBe("toctou-client");
    }
    // Verify findByIdentifier was called twice (initial + retry)
    expect(findCallCount).toBe(2);
  });

  it("save conflict with different commitment results in failure (not idempotent)", async () => {
    let saveCallCount = 0;
    const existingClient = Client.register(
      ClientId.fromBytes(new Uint8Array(16).fill(7)),
      "conflict-client",
      Commitment.fromBytes(new Uint8Array(32).fill(99)), // Different commitment
    );

    const repository: ClientRepository = {
      save: async () => {
        saveCallCount++;
        if (saveCallCount >= 1) {
          throw new Error("Optimistic concurrency conflict");
        }
      },
      update: async () => {},
      findByIdentifier: async (identifier: string) => {
        // On retry, return existing client with DIFFERENT commitment
        if (saveCallCount >= 1) return existingClient;
        return null;
      },
      existsByIdentifier: async () => false,
    };

    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest("conflict-client", 42));

    expect(result).toEqual({ success: false, error: "enrollment_failed" });
  });
});
