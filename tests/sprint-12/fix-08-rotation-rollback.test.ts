// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RotateCommitmentUseCase } from "../../src/client-registration/application/usecase/rotate-commitment.usecase.js";
import { RotationPolicy } from "../../src/client-registration/domain/service/rotation-policy.js";
import type { ClientRepository } from "../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type { RotationProofVerifier } from "../../src/client-registration/domain/port/outgoing/rotation-proof-verifier.js";
import type { TokenInvalidator } from "../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import { Client } from "../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../src/client-registration/domain/model/commitment.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createNoopRateLimiter,
} from "../helpers/enrollment-test-helpers.js";

function createActiveClient(identifier: string = "client-1"): Client {
  return Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
}

function createStubCommitmentVerifier(): CommitmentVerifier {
  return {
    isCanonical: () => true,
    isValidGroupElement: () => true,
    isIdentityElement: () => false,
  };
}

function createStubRotationProofVerifier(): RotationProofVerifier {
  return { verify: () => true };
}

describe("FIX 8 — Rotation Rollback Inconsistency", () => {
  it("event publish failure → commitment rolled back, tokens NOT invalidated", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const executionOrder: string[] = [];

    let updateCount = 0;
    const repository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        updateCount++;
        repository.updatedClients.push(client);
        clients.set(client.identifier, client);
        executionOrder.push("repository.update");
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const tokenInvalidator: TokenInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        tokenInvalidator.invalidatedClients.push(id);
        executionOrder.push("tokenInvalidator.invalidate");
      },
    };

    const challengeInvalidator: ChallengeInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        challengeInvalidator.invalidatedClients.push(id);
        executionOrder.push("challengeInvalidator.invalidate");
      },
    };

    const failingEventPublisher = {
      events: [] as any[],
      publish: async () => {
        executionOrder.push("eventPublisher.publish_FAIL");
        throw new Error("Event bus unavailable");
      },
    };

    const auditLogger = createCapturingAuditLogger();
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(),
    );

    const useCase = new RotateCommitmentUseCase(
      policy,
      repository,
      tokenInvalidator,
      challengeInvalidator,
      auditLogger,
      failingEventPublisher,
      createNoopRateLimiter(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      currentProofBytes: new Uint8Array(32).fill(1),
      newCommitmentBytes: new Uint8Array(32).fill(0xcd),
      newCommitmentProofBytes: new Uint8Array(32).fill(2),
    });

    expect(result).toEqual({ success: false, error: "rotation_failed" });

    // Tokens should NOT have been invalidated (event publish failed BEFORE invalidation)
    expect(tokenInvalidator.invalidatedClients).toHaveLength(0);
    expect(challengeInvalidator.invalidatedClients).toHaveLength(0);

    // Commitment should have been rolled back (two updates: new + rollback to original)
    expect(updateCount).toBe(2);
  });

  it("token invalidation failure after event published → commitment stays, warning logged", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const executionOrder: string[] = [];

    const repository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        repository.updatedClients.push(client);
        clients.set(client.identifier, client);
        executionOrder.push("repository.update");
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const failingTokenInvalidator: TokenInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async () => {
        executionOrder.push("tokenInvalidator.invalidate_FAIL");
        throw new Error("Token service unavailable");
      },
    };

    const challengeInvalidator: ChallengeInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        challengeInvalidator.invalidatedClients.push(id);
        executionOrder.push("challengeInvalidator.invalidate");
      },
    };

    const eventPublisher = createCapturingEventPublisher();
    const auditLogger = createCapturingAuditLogger();

    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(),
    );

    const useCase = new RotateCommitmentUseCase(
      policy,
      repository,
      failingTokenInvalidator,
      challengeInvalidator,
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      currentProofBytes: new Uint8Array(32).fill(1),
      newCommitmentBytes: new Uint8Array(32).fill(0xcd),
      newCommitmentProofBytes: new Uint8Array(32).fill(2),
    });

    // Rotation succeeds — event was published, commitment stays
    expect(result).toEqual({ success: true });

    // Event was published
    expect(eventPublisher.events.length).toBe(1);
    expect(eventPublisher.events[0]!.eventType).toBe("CommitmentRotated");

    // Warning logged about token invalidation failure
    const warningEntry = auditLogger.events.find(
      (e: any) => e.metadata?.reason === "TOKEN_INVALIDATION_FAILED",
    );
    expect(warningEntry).toBeDefined();
  });

  it("new ordering: save → publish → invalidate (not save → invalidate → publish)", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const executionOrder: string[] = [];

    const repository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        repository.updatedClients.push(client);
        clients.set(client.identifier, client);
        executionOrder.push("repository.update");
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const tokenInvalidator: TokenInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        tokenInvalidator.invalidatedClients.push(id);
        executionOrder.push("tokenInvalidator.invalidate");
      },
    };

    const challengeInvalidator: ChallengeInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        challengeInvalidator.invalidatedClients.push(id);
        executionOrder.push("challengeInvalidator.invalidate");
      },
    };

    const eventPublisher = {
      events: [] as any[],
      publish: async (event: any) => {
        eventPublisher.events.push(event);
        executionOrder.push("eventPublisher.publish");
      },
    };

    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(),
    );

    const useCase = new RotateCommitmentUseCase(
      policy,
      repository,
      tokenInvalidator,
      challengeInvalidator,
      createCapturingAuditLogger(),
      eventPublisher,
      createNoopRateLimiter(),
    );

    await useCase.execute({
      clientIdentifier: "client-1",
      currentProofBytes: new Uint8Array(32).fill(1),
      newCommitmentBytes: new Uint8Array(32).fill(0xcd),
      newCommitmentProofBytes: new Uint8Array(32).fill(2),
    });

    // New ordering: save → publish → invalidate tokens → invalidate challenges
    expect(executionOrder).toEqual([
      "repository.update",
      "eventPublisher.publish",
      "tokenInvalidator.invalidate",
      "challengeInvalidator.invalidate",
    ]);
  });
});
