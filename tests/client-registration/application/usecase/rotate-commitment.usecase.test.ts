// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RotateCommitmentUseCase } from "../../../../src/client-registration/application/usecase/rotate-commitment.usecase.js";
import { RotationPolicy } from "../../../../src/client-registration/domain/service/rotation-policy.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "../../../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type { RotationProofVerifier } from "../../../../src/client-registration/domain/port/outgoing/rotation-proof-verifier.js";
import type { TokenInvalidator } from "../../../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import type { RateLimiter } from "../../../../src/client-registration/domain/port/outgoing/rate-limiter.js";
import type { RotateCommitmentRequest } from "../../../../src/client-registration/domain/port/incoming/rotate-commitment.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";
import type { RecoveryHashStore } from "../../../../src/client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { RecoveryPhraseGenerator } from "../../../../src/client-registration/domain/service/recovery-phrase-generator.js";
import { RecoveryPhrase } from "../../../../src/client-registration/domain/model/recovery-phrase.js";
import { RecoveryConfig } from "../../../../src/client-registration/domain/model/recovery-config.js";
import type { Argon2Hasher, Argon2Params } from "../../../../src/client-registration/domain/port/outgoing/argon2-hasher.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createNoopRateLimiter,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Test Helpers ---

function createActiveClient(identifier: string = "client-1", commitmentByte: number = 0xab): Client {
  return Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(commitmentByte)),
  );
}

function createStubClientRepository(
  clients: Map<string, Client> = new Map(),
): ClientRepository & { updatedClients: Client[] } {
  const updatedClients: Client[] = [];
  return {
    updatedClients,
    save: async () => {},
    update: async (client: Client) => {
      updatedClients.push(client);
      clients.set(client.identifier, client);
    },
    findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
    existsByIdentifier: async (identifier: string) => clients.has(identifier),
  };
}

function createStubCommitmentVerifier(
  overrides: Partial<CommitmentVerifier> = {},
): CommitmentVerifier {
  return {
    isCanonical: overrides.isCanonical ?? (() => true),
    isValidGroupElement: overrides.isValidGroupElement ?? (() => true),
    isIdentityElement: overrides.isIdentityElement ?? (() => false),
  };
}

function createStubRotationProofVerifier(valid: boolean = true): RotationProofVerifier {
  return {
    verify: () => valid,
  };
}

function createStubTokenInvalidator(): TokenInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

function createStubChallengeInvalidator(): ChallengeInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

function createStubRecoveryHashStore(
  hashes: Map<string, Uint8Array> = new Map(),
): RecoveryHashStore & { storedHashes: Map<string, Uint8Array> } {
  return {
    storedHashes: hashes,
    storeHash: async (id: string, hash: Uint8Array) => { hashes.set(id, hash); },
    getHash: async (id: string) => hashes.get(id) ?? null,
    recordFailedAttempt: async () => 0,
    resetAttempts: async () => {},
    getAttemptCount: async () => 0,
    deleteHash: async (id: string) => { hashes.delete(id); },
  };
}

const ROTATION_RECOVERY_WORDS = [
  "zoo", "zone", "zebra", "year",
  "yellow", "young", "youth", "yard",
  "yoga", "yawn", "yacht", "zero",
];

function createStubPhraseGenerator(): RecoveryPhraseGenerator {
  return {
    generate: () => RecoveryPhrase.create([...ROTATION_RECOVERY_WORDS]),
  };
}

function createStubArgon2Hasher(): Argon2Hasher {
  return {
    hash: async (input: Uint8Array) => {
      const result = new Uint8Array(32);
      for (let i = 0; i < Math.min(input.length, 32); i++) {
        result[i] = input[i]!;
      }
      return result;
    },
    verify: async () => true,
  };
}

function validRotateRequest(
  identifier: string = "client-1",
  newCommitmentByte: number = 0xcd,
): RotateCommitmentRequest {
  return {
    clientIdentifier: identifier,
    currentProofBytes: new Uint8Array(32).fill(1),
    newCommitmentBytes: new Uint8Array(32).fill(newCommitmentByte),
    newCommitmentProofBytes: new Uint8Array(32).fill(2),
  };
}

function createUseCase(overrides: {
  clients?: Map<string, Client>;
  commitmentVerifier?: CommitmentVerifier;
  rotationProofVerifier?: RotationProofVerifier;
  tokenInvalidator?: TokenInvalidator & { invalidatedClients: string[] };
  challengeInvalidator?: ChallengeInvalidator & { invalidatedClients: string[] };
  auditLogger?: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher?: ReturnType<typeof createCapturingEventPublisher>;
  rateLimiter?: RateLimiter;
  repository?: ClientRepository & { updatedClients: Client[] };
  recoveryHashStore?: RecoveryHashStore;
  phraseGenerator?: RecoveryPhraseGenerator;
  argon2Hasher?: Argon2Hasher;
  recoveryConfig?: RecoveryConfig;
} = {}) {
  const commitmentVerifier = overrides.commitmentVerifier ?? createStubCommitmentVerifier();
  const rotationProofVerifier = overrides.rotationProofVerifier ?? createStubRotationProofVerifier(true);
  const repository = overrides.repository ?? createStubClientRepository(overrides.clients ?? new Map());
  const tokenInvalidator = overrides.tokenInvalidator ?? createStubTokenInvalidator();
  const challengeInvalidator = overrides.challengeInvalidator ?? createStubChallengeInvalidator();
  const auditLogger = overrides.auditLogger ?? createCapturingAuditLogger();
  const eventPublisher = overrides.eventPublisher ?? createCapturingEventPublisher();
  const rateLimiter = overrides.rateLimiter ?? createNoopRateLimiter();

  const policy = new RotationPolicy(commitmentVerifier, rotationProofVerifier);

  const useCase = new RotateCommitmentUseCase(
    policy,
    repository,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger,
    eventPublisher,
    rateLimiter,
    overrides.recoveryHashStore && overrides.phraseGenerator && overrides.argon2Hasher
      ? {
          recoveryHashStore: overrides.recoveryHashStore,
          phraseGenerator: overrides.phraseGenerator,
          argon2Hasher: overrides.argon2Hasher,
          recoveryConfig: overrides.recoveryConfig ?? RecoveryConfig.defaults(),
        }
      : undefined,
  );

  return { useCase, repository, tokenInvalidator, challengeInvalidator, auditLogger, eventPublisher };
}

describe("RotateCommitmentUseCase", () => {
  it("happy path: valid proof + new commitment → replaced, tokens invalidated, event published, audit logged", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, repository, tokenInvalidator, challengeInvalidator, auditLogger, eventPublisher } = createUseCase({ clients });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: true });

    // Commitment replaced
    expect(repository.updatedClients.length).toBe(1);
    expect(repository.updatedClients[0]!.commitment.toBytes()).toEqual(new Uint8Array(32).fill(0xcd));
    expect(repository.updatedClients[0]!.status).toBe("active");

    // Tokens invalidated
    expect(tokenInvalidator.invalidatedClients).toEqual(["client-1"]);

    // Challenges invalidated
    expect(challengeInvalidator.invalidatedClients).toEqual(["client-1"]);

    // Event published
    expect(eventPublisher.events.length).toBe(1);
    expect(eventPublisher.events[0]!.eventType).toBe("CommitmentRotated");

    // Audit logged
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("commitment_rotated");
    expect(auditLogger.events[0]!.clientIdentifier).toBe("client-1");
  });

  it("commitment version increments on rotation (not hardcoded)", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const eventPublisher = createCapturingEventPublisher();
    const { useCase, repository } = createUseCase({ clients, eventPublisher });

    // First rotation: version should go from 1 to 2
    await useCase.execute(validRotateRequest());

    expect(eventPublisher.events.length).toBe(1);
    const event1 = eventPublisher.events[0] as any;
    expect(event1.commitmentVersion).toBe(2);

    // The stored client should have commitmentVersion = 2
    const storedClient1 = await repository.findByIdentifier("client-1");
    expect(storedClient1!.commitmentVersion).toBe(2);

    // Second rotation: version should go from 2 to 3
    await useCase.execute({
      clientIdentifier: "client-1",
      currentProofBytes: new Uint8Array(32).fill(1),
      newCommitmentBytes: new Uint8Array(32).fill(0xef),
      newCommitmentProofBytes: new Uint8Array(32).fill(2),
    });

    expect(eventPublisher.events.length).toBe(2);
    const event2 = eventPublisher.events[1] as any;
    expect(event2.commitmentVersion).toBe(3);
  });

  it("same commitment → refused", async () => {
    const activeClient = createActiveClient("client-1", 0xcd);
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({ clients });

    const result = await useCase.execute(validRotateRequest("client-1", 0xcd));

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "SAME_COMMITMENT" }),
    );
  });

  it("identity element as new commitment → refused", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({
      clients,
      commitmentVerifier: createStubCommitmentVerifier({ isIdentityElement: () => true }),
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "IDENTITY_ELEMENT" }),
    );
  });

  it("non-canonical encoding → refused", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({
      clients,
      commitmentVerifier: createStubCommitmentVerifier({ isCanonical: () => false }),
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "INVALID_ENCODING" }),
    );
  });

  it("invalid proof of current commitment → refused", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({
      clients,
      rotationProofVerifier: createStubRotationProofVerifier(false),
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "INVALID_CURRENT_PROOF" }),
    );
  });

  it("revoked client → refused (indistinguishable)", async () => {
    const activeClient = createActiveClient();
    const revokedClient = activeClient.revoke();
    const clients = new Map([["client-1", revokedClient]]);
    const { useCase, auditLogger } = createUseCase({ clients });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("rotation_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "CLIENT_NOT_ACTIVE" }),
    );
  });

  it("unknown client → refused (indistinguishable)", async () => {
    const { useCase, auditLogger } = createUseCase();

    const result = await useCase.execute(validRotateRequest("unknown-client"));

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("rotation_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "CLIENT_NOT_FOUND" }),
    );
  });

  it("event publisher failure → rollback (update not persisted)", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);

    let updateCount = 0;
    const repositoryWithRollback: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        updateCount++;
        repositoryWithRollback.updatedClients.push(client);
        clients.set(client.identifier, client);
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const failingEventPublisher = {
      events: [] as any[],
      publish: async () => {
        throw new Error("Event bus unavailable");
      },
    };

    const { useCase, auditLogger } = createUseCase({
      repository: repositoryWithRollback,
      eventPublisher: failingEventPublisher,
    });

    const result = await useCase.execute(validRotateRequest());

    // Rotation should fail on event publisher failure
    expect(result).toEqual({ success: false, error: "rotation_failed" });
    // Rollback: should update twice (first the new commitment, then rollback to original)
    expect(updateCount).toBe(2);
    // Audit logs the event publish failure
    const failedAudit = auditLogger.events.find((e: any) => e.metadata?.reason === "EVENT_PUBLISH_FAILED");
    expect(failedAudit).toBeDefined();
    expect(failedAudit!.eventType).toBe("rotation_failed");
  });

  it("rate limited → refused", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({
      clients,
      rateLimiter: { isAllowed: async () => false },
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "RATE_LIMITED" }),
    );
  });

  it("allowed rate limiter allows rotation (if !allowed should block, not if true)", async () => {
    // Kill mutant: `if (true)` instead of `if (!allowed)`
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase } = createUseCase({
      clients,
      rateLimiter: { isAllowed: async () => true },
    });

    const result = await useCase.execute(validRotateRequest());
    // With `if (true)`, this would always fail
    expect(result).toEqual({ success: true });
  });

  it("rate limited audit includes 'rotation_failed' eventType (not empty string)", async () => {
    // Kill mutant: eventType: "" instead of "rotation_failed"
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({
      clients,
      rateLimiter: { isAllowed: async () => false },
    });

    await useCase.execute(validRotateRequest());

    expect(auditLogger.events[0]!.eventType).toBe("rotation_failed");
    expect(auditLogger.events[0]!.eventType.length).toBeGreaterThan(0);
  });

  it("same commitment audit includes 'rotation_failed' eventType (not empty string)", async () => {
    // Kill mutant: eventType: "" instead of "rotation_failed" on line 65
    const activeClient = createActiveClient("client-1", 0xcd);
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, auditLogger } = createUseCase({ clients });

    await useCase.execute(validRotateRequest("client-1", 0xcd));

    expect(auditLogger.events[0]!.eventType).toBe("rotation_failed");
    expect(auditLogger.events[0]!.eventType.length).toBeGreaterThan(0);
  });

  it("all error responses have identical shape", async () => {
    const expectedFailure = { success: false, error: "rotation_failed" };

    // Unknown client
    const { useCase: uc1 } = createUseCase();
    expect(await uc1.execute(validRotateRequest("unknown"))).toEqual(expectedFailure);

    // Same commitment
    const client2 = createActiveClient("c2", 0xcd);
    const { useCase: uc2 } = createUseCase({ clients: new Map([["c2", client2]]) });
    expect(await uc2.execute(validRotateRequest("c2", 0xcd))).toEqual(expectedFailure);

    // Invalid encoding
    const client3 = createActiveClient("c3");
    const { useCase: uc3 } = createUseCase({
      clients: new Map([["c3", client3]]),
      commitmentVerifier: createStubCommitmentVerifier({ isCanonical: () => false }),
    });
    expect(await uc3.execute(validRotateRequest("c3"))).toEqual(expectedFailure);

    // Invalid proof
    const client4 = createActiveClient("c4");
    const { useCase: uc4 } = createUseCase({
      clients: new Map([["c4", client4]]),
      rotationProofVerifier: createStubRotationProofVerifier(false),
    });
    expect(await uc4.execute(validRotateRequest("c4"))).toEqual(expectedFailure);

    // Revoked
    const client5 = createActiveClient("c5").revoke();
    const { useCase: uc5 } = createUseCase({ clients: new Map([["c5", client5]]) });
    expect(await uc5.execute(validRotateRequest("c5"))).toEqual(expectedFailure);

    // Rate limited
    const client6 = createActiveClient("c6");
    const { useCase: uc6 } = createUseCase({
      clients: new Map([["c6", client6]]),
      rateLimiter: { isAllowed: async () => false },
    });
    expect(await uc6.execute(validRotateRequest("c6"))).toEqual(expectedFailure);
  });

  it("no update on failed rotation", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase, repository } = createUseCase({
      clients,
      rotationProofVerifier: createStubRotationProofVerifier(false),
    });

    await useCase.execute(validRotateRequest());

    expect(repository.updatedClients.length).toBe(0);
  });

  it("no tokens/challenges invalidated on failed rotation", async () => {
    const { useCase, tokenInvalidator, challengeInvalidator } = createUseCase();

    await useCase.execute(validRotateRequest("unknown"));

    expect(tokenInvalidator.invalidatedClients.length).toBe(0);
    expect(challengeInvalidator.invalidatedClients.length).toBe(0);
  });

  it("operations execute in order: save → publish event → invalidate tokens → invalidate challenges", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const executionOrder: string[] = [];

    const orderTrackingRepository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        orderTrackingRepository.updatedClients.push(client);
        clients.set(client.identifier, client);
        executionOrder.push("repository.update");
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const orderTrackingTokenInvalidator: TokenInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        orderTrackingTokenInvalidator.invalidatedClients.push(id);
        executionOrder.push("tokenInvalidator.invalidateAllForClient");
      },
    };

    const orderTrackingChallengeInvalidator: ChallengeInvalidator & { invalidatedClients: string[] } = {
      invalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        orderTrackingChallengeInvalidator.invalidatedClients.push(id);
        executionOrder.push("challengeInvalidator.invalidateAllForClient");
      },
    };

    const orderTrackingEventPublisher = {
      events: [] as any[],
      publish: async (event: any) => {
        orderTrackingEventPublisher.events.push(event);
        executionOrder.push("eventPublisher.publish");
      },
    };

    const { useCase } = createUseCase({
      repository: orderTrackingRepository,
      tokenInvalidator: orderTrackingTokenInvalidator,
      challengeInvalidator: orderTrackingChallengeInvalidator,
      eventPublisher: orderTrackingEventPublisher,
      clients,
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: true });
    expect(executionOrder).toEqual([
      "repository.update",
      "eventPublisher.publish",
      "tokenInvalidator.invalidateAllForClient",
      "challengeInvalidator.invalidateAllForClient",
    ]);
  });

  it("event publisher failure rollback undoes token and challenge invalidation", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const executionOrder: string[] = [];

    let updateCount = 0;
    const rollbackRepository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        updateCount++;
        rollbackRepository.updatedClients.push(client);
        clients.set(client.identifier, client);
        executionOrder.push("repository.update");
      },
      findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const rollbackTokenInvalidator: TokenInvalidator & { invalidatedClients: string[]; revalidatedClients: string[] } = {
      invalidatedClients: [],
      revalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        rollbackTokenInvalidator.invalidatedClients.push(id);
        executionOrder.push("tokenInvalidator.invalidateAllForClient");
      },
    };

    const rollbackChallengeInvalidator: ChallengeInvalidator & { invalidatedClients: string[]; revalidatedClients: string[] } = {
      invalidatedClients: [],
      revalidatedClients: [],
      invalidateAllForClient: async (id: string) => {
        rollbackChallengeInvalidator.invalidatedClients.push(id);
        executionOrder.push("challengeInvalidator.invalidateAllForClient");
      },
    };

    const failingEventPublisher = {
      events: [] as any[],
      publish: async () => {
        executionOrder.push("eventPublisher.publish_FAIL");
        throw new Error("Event bus unavailable");
      },
    };

    const { useCase } = createUseCase({
      repository: rollbackRepository,
      tokenInvalidator: rollbackTokenInvalidator,
      challengeInvalidator: rollbackChallengeInvalidator,
      eventPublisher: failingEventPublisher,
      clients,
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    // New ordering: update (new) -> publish (fail) -> rollback update (original)
    // Tokens and challenges are NOT invalidated because event publish failed first
    expect(executionOrder[0]).toBe("repository.update");
    expect(executionOrder).toContain("eventPublisher.publish_FAIL");
    expect(executionOrder).not.toContain("tokenInvalidator.invalidateAllForClient");
    expect(executionOrder).not.toContain("challengeInvalidator.invalidateAllForClient");
    // Rollback should restore original commitment
    expect(updateCount).toBe(2);
  });

  it("detects concurrent revocation and aborts rotation (BB02)", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);

    let readCount = 0;
    const racyRepository: ClientRepository & { updatedClients: Client[] } = {
      updatedClients: [],
      save: async () => {},
      update: async (client: Client) => {
        racyRepository.updatedClients.push(client);
        clients.set(client.identifier, client);
      },
      findByIdentifier: async (identifier: string) => {
        readCount++;
        // First read returns active, second read returns revoked (simulating concurrent revocation)
        if (readCount === 2) {
          return activeClient.revoke();
        }
        return clients.get(identifier) ?? null;
      },
      existsByIdentifier: async (identifier: string) => clients.has(identifier),
    };

    const { useCase, auditLogger } = createUseCase({ repository: racyRepository });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: false, error: "rotation_failed" });
    const failEvent = auditLogger.events.find((e: any) => e.metadata?.reason === "CONCURRENT_STATUS_CHANGE");
    expect(failEvent).toBeDefined();
    expect(racyRepository.updatedClients.length).toBe(0);
  });

  it("generates new recovery hash after rotation (BF02)", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const oldHash = new Uint8Array(32).fill(0xab);
    const hashes = new Map([["client-1", oldHash]]);
    const recoveryHashStore = createStubRecoveryHashStore(hashes);

    const { useCase } = createUseCase({
      clients,
      recoveryHashStore,
      phraseGenerator: createStubPhraseGenerator(),
      argon2Hasher: createStubArgon2Hasher(),
    });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: true });
    // Old hash should be replaced with new hash
    const newHash = recoveryHashStore.storedHashes.get("client-1");
    expect(newHash).toBeDefined();
    expect(newHash).not.toEqual(oldHash);
  });

  it("skips rate limiting when no rate limiter is provided", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const { useCase } = createUseCase({ clients });

    const result = await useCase.execute(validRotateRequest());

    expect(result).toEqual({ success: true });
  });
});
