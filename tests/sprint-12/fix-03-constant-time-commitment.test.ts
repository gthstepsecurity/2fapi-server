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
  return {
    generate: () => ClientId.fromBytes(new Uint8Array(16).fill(99)),
  };
}

function createClientWithCommitment(
  identifier: string,
  commitmentByte: number,
): Client {
  return Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(commitmentByte)),
  );
}

describe("FIX 3 — Constant-Time Commitment Comparison in Enrollment", () => {
  it("idempotent enrollment succeeds with same commitment (constant-time path)", async () => {
    const existingClient = createClientWithCommitment("test-client-1", 42);
    const clients = new Map<string, Client>([["test-client-1", existingClient]]);

    const repository: ClientRepository & { savedClients: Client[] } = {
      savedClients: [],
      save: async (client: Client) => {
        repository.savedClients.push(client);
        clients.set(client.identifier, client);
      },
      update: async () => {},
      findByIdentifier: async (id: string) => clients.get(id) ?? null,
      existsByIdentifier: async (id: string) => clients.has(id),
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

    const result = await useCase.execute(validRequest("test-client-1", 42));

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.referenceId).toBe(existingClient.id.toString());
    }
  });

  it("enrollment fails with different commitment (constant-time path)", async () => {
    const existingClient = createClientWithCommitment("test-client-1", 42);
    const clients = new Map<string, Client>([["test-client-1", existingClient]]);

    const repository: ClientRepository = {
      save: async () => {},
      update: async () => {},
      findByIdentifier: async (id: string) => clients.get(id) ?? null,
      existsByIdentifier: async (id: string) => clients.has(id),
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

    const result = await useCase.execute(validRequest("test-client-1", 99));

    expect(result).toEqual({ success: false, error: "enrollment_failed" });
  });
});
