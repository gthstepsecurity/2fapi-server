// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RecoverViaPhraseUseCase } from "../../../../src/client-registration/application/usecase/recover-via-phrase.usecase.js";
import { ConcurrencyLimiter } from "../../../../src/shared/concurrency-limiter.js";
import type { RecoverViaPhraseRequest } from "../../../../src/client-registration/domain/port/incoming/recover-via-phrase.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { RecoveryHashStore } from "../../../../src/client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { Argon2Hasher, Argon2Params } from "../../../../src/client-registration/domain/port/outgoing/argon2-hasher.js";
import type { TokenInvalidator } from "../../../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";
import { RecoveryConfig } from "../../../../src/client-registration/domain/model/recovery-config.js";
import type { RecoveryPhraseGenerator } from "../../../../src/client-registration/domain/service/recovery-phrase-generator.js";
import { RecoveryPhrase } from "../../../../src/client-registration/domain/model/recovery-phrase.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Test Helpers ---

const CORRECT_WORDS = [
  "abandon", "ability", "able", "about",
  "above", "absent", "absorb", "abstract",
  "absurd", "abuse", "access", "accident",
];

const WRONG_WORDS = [
  "zoo", "zone", "zero", "year",
  "wrong", "write", "world", "wonder",
  "witness", "window", "winter", "wild",
];

function createSuspendedClient(identifier: string = "alice-payment-service"): Client {
  const active = Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
  return active.suspend();
}

function createActiveClient(identifier: string = "alice-payment-service"): Client {
  return Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
}

function createRevokedClient(identifier: string = "alice-payment-service"): Client {
  const active = Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
  return active.revoke();
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

function createStubRecoveryHashStore(
  hashes: Map<string, Uint8Array> = new Map(),
  failedAttempts: Map<string, number> = new Map(),
): RecoveryHashStore & { storedHashes: Map<string, Uint8Array>; attempts: Map<string, number> } {
  return {
    storedHashes: hashes,
    attempts: failedAttempts,
    storeHash: async (clientIdentifier: string, hash: Uint8Array) => {
      hashes.set(clientIdentifier, hash);
    },
    getHash: async (clientIdentifier: string) => hashes.get(clientIdentifier) ?? null,
    recordFailedAttempt: async (clientIdentifier: string) => {
      const current = failedAttempts.get(clientIdentifier) ?? 0;
      const next = current + 1;
      failedAttempts.set(clientIdentifier, next);
      return next;
    },
    resetAttempts: async (clientIdentifier: string) => {
      failedAttempts.set(clientIdentifier, 0);
    },
    getAttemptCount: async (clientIdentifier: string) => {
      return failedAttempts.get(clientIdentifier) ?? 0;
    },
    deleteHash: async (clientIdentifier: string) => {
      hashes.delete(clientIdentifier);
      failedAttempts.delete(clientIdentifier);
    },
  };
}

function createMatchingArgon2Hasher(): Argon2Hasher {
  return {
    hash: async (input: Uint8Array, _salt: Uint8Array, _params: Argon2Params) => {
      // Simple deterministic hash for tests
      const result = new Uint8Array(32);
      for (let i = 0; i < Math.min(input.length, 32); i++) {
        result[i] = input[i]!;
      }
      return result;
    },
    verify: async () => true,
  };
}

function createNonMatchingArgon2Hasher(): Argon2Hasher {
  return {
    hash: async () => new Uint8Array(32),
    verify: async () => false,
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

const NEW_RECOVERY_WORDS = [
  "zoo", "zone", "zebra", "year",
  "yellow", "young", "youth", "yard",
  "yoga", "yawn", "yacht", "zero",
];

function createStubPhraseGenerator(): RecoveryPhraseGenerator {
  return {
    generate: () => RecoveryPhrase.create([...NEW_RECOVERY_WORDS]),
  };
}

function validRecoveryRequest(
  identifier: string = "alice-payment-service",
  words: readonly string[] = CORRECT_WORDS,
): RecoverViaPhraseRequest {
  return {
    clientIdentifier: identifier,
    words,
    newCommitmentBytes: new Uint8Array(32).fill(0xbb),
    newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
  };
}

function createUseCase(overrides: {
  repository?: ClientRepository;
  recoveryHashStore?: RecoveryHashStore;
  argon2Hasher?: Argon2Hasher;
  tokenInvalidator?: TokenInvalidator;
  challengeInvalidator?: ChallengeInvalidator;
  auditLogger?: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher?: ReturnType<typeof createCapturingEventPublisher>;
  config?: RecoveryConfig;
  concurrencyLimiter?: ConcurrencyLimiter;
  phraseGenerator?: RecoveryPhraseGenerator;
} = {}) {
  const repository = overrides.repository ?? createStubClientRepository();
  const recoveryHashStore = overrides.recoveryHashStore ?? createStubRecoveryHashStore();
  const argon2Hasher = overrides.argon2Hasher ?? createMatchingArgon2Hasher();
  const tokenInvalidator = overrides.tokenInvalidator ?? createStubTokenInvalidator();
  const challengeInvalidator = overrides.challengeInvalidator ?? createStubChallengeInvalidator();
  const auditLogger = overrides.auditLogger ?? createCapturingAuditLogger();
  const eventPublisher = overrides.eventPublisher ?? createCapturingEventPublisher();
  const config = overrides.config ?? RecoveryConfig.defaults();

  const options: {
    concurrencyLimiter?: ConcurrencyLimiter;
    phraseGenerator?: RecoveryPhraseGenerator;
  } = {};
  if (overrides.concurrencyLimiter) options.concurrencyLimiter = overrides.concurrencyLimiter;
  if (overrides.phraseGenerator) options.phraseGenerator = overrides.phraseGenerator;

  return new RecoverViaPhraseUseCase(
    repository,
    recoveryHashStore,
    argon2Hasher,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger,
    eventPublisher,
    config,
    Object.keys(options).length > 0 ? options : undefined,
  );
}

describe("RecoverViaPhraseUseCase", () => {
  describe("successful recovery", () => {
    it("suspended client with correct words: recovery succeeds", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({ repository, recoveryHashStore });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: true });
    });

    it("reactivates client with new commitment", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({ repository, recoveryHashStore });

      await useCase.execute(validRecoveryRequest());

      expect(repository.updatedClients.length).toBe(1);
      expect(repository.updatedClients[0]!.status).toBe("active");
      expect(repository.updatedClients[0]!.commitment.toBytes()).toEqual(new Uint8Array(32).fill(0xbb));
    });

    it("increments commitment version on recovery", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({ repository, recoveryHashStore });

      await useCase.execute(validRecoveryRequest());

      expect(repository.updatedClients[0]!.commitmentVersion).toBe(client.commitmentVersion + 1);
    });

    it("resets failed attempt counter on successful recovery", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const failedAttempts = new Map([["alice-payment-service", 2]]);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes, failedAttempts);

      const useCase = createUseCase({ repository, recoveryHashStore });

      await useCase.execute(validRecoveryRequest());

      expect(recoveryHashStore.attempts.get("alice-payment-service")).toBe(0);
    });

    it("publishes ClientRecovered event with method 'phrase'", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const eventPublisher = createCapturingEventPublisher();

      const useCase = createUseCase({ repository, recoveryHashStore, eventPublisher });

      await useCase.execute(validRecoveryRequest());

      expect(eventPublisher.events.length).toBe(1);
      expect(eventPublisher.events[0]!.eventType).toBe("ClientRecovered");
    });

    it("logs recovery in audit trail", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({ repository, recoveryHashStore, auditLogger });

      await useCase.execute(validRecoveryRequest());

      const auditEvent = auditLogger.events.find((e) => e.eventType === "client_recovered");
      expect(auditEvent).toBeDefined();
      expect(auditEvent!.clientIdentifier).toBe("alice-payment-service");
    });

    it("invalidates old tokens and challenges", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const tokenInvalidator = createStubTokenInvalidator();
      const challengeInvalidator = createStubChallengeInvalidator();

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        tokenInvalidator,
        challengeInvalidator,
      });

      await useCase.execute(validRecoveryRequest());

      expect(tokenInvalidator.invalidatedClients).toEqual(["alice-payment-service"]);
      expect(challengeInvalidator.invalidatedClients).toEqual(["alice-payment-service"]);
    });

    it("generates new recovery hash after successful recovery (BA11)", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const oldHash = new Uint8Array(32).fill(0xab);
      const hashes = new Map([["alice-payment-service", oldHash]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        phraseGenerator: createStubPhraseGenerator(),
      });

      await useCase.execute(validRecoveryRequest());

      // After recovery, the old hash should be replaced with a new one
      const newHash = recoveryHashStore.storedHashes.get("alice-payment-service");
      expect(newHash).toBeDefined();
      // New hash must differ from old hash (new phrase was generated)
      expect(newHash).not.toEqual(oldHash);
    });

    it("detects concurrent recovery and aborts (BB08)", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);

      let readCount = 0;
      const racyRepository: ClientRepository & { updatedClients: Client[] } = {
        updatedClients: [],
        save: async () => {},
        update: async (c: Client) => {
          racyRepository.updatedClients.push(c);
          clients.set(c.identifier, c);
        },
        findByIdentifier: async (identifier: string) => {
          readCount++;
          // Second read simulates concurrent recovery having bumped the version
          if (readCount === 2) {
            return Client.reconstitute(
              client.id,
              client.identifier,
              Commitment.fromBytes(new Uint8Array(32).fill(0xff)),
              "active",
              client.commitmentVersion + 1,
            );
          }
          return clients.get(identifier) ?? null;
        },
        existsByIdentifier: async () => true,
      };

      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({
        repository: racyRepository,
        recoveryHashStore,
        auditLogger,
      });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
      const failEvent = auditLogger.events.find((e: any) => e.metadata?.reason === "CONCURRENT_RECOVERY");
      expect(failEvent).toBeDefined();
      expect(racyRepository.updatedClients.length).toBe(0);
    });

    it("old recovery phrase no longer works after recovery (BA11)", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const oldHash = new Uint8Array(32).fill(0xab);
      const hashes = new Map([["alice-payment-service", oldHash]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        phraseGenerator: createStubPhraseGenerator(),
      });

      await useCase.execute(validRecoveryRequest());

      // The stored hash has changed — old words would not match the new hash
      const currentHash = recoveryHashStore.storedHashes.get("alice-payment-service");
      expect(currentHash).not.toEqual(oldHash);
    });
  });

  describe("recovery failures — indistinguishable responses", () => {
    it("wrong words: returns recovery_failed", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: createNonMatchingArgon2Hasher(),
      });

      const result = await useCase.execute(validRecoveryRequest("alice-payment-service", WRONG_WORDS));

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("wrong words: increments failed attempt counter", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const failedAttempts = new Map<string, number>();
      const recoveryHashStore = createStubRecoveryHashStore(hashes, failedAttempts);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: createNonMatchingArgon2Hasher(),
      });

      await useCase.execute(validRecoveryRequest("alice-payment-service", WRONG_WORDS));

      expect(recoveryHashStore.attempts.get("alice-payment-service")).toBe(1);
    });

    it("3 failed attempts: locks recovery permanently", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const failedAttempts = new Map([["alice-payment-service", 2]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes, failedAttempts);
      const eventPublisher = createCapturingEventPublisher();

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: createNonMatchingArgon2Hasher(),
        eventPublisher,
      });

      const result = await useCase.execute(validRecoveryRequest("alice-payment-service", WRONG_WORDS));

      expect(result).toEqual({ success: false, error: "recovery_failed" });
      expect(recoveryHashStore.attempts.get("alice-payment-service")).toBe(3);
    });

    it("non-suspended (active) client: returns recovery_failed (indistinguishable)", async () => {
      const client = createActiveClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);

      const useCase = createUseCase({ repository });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("revoked client: returns recovery_failed (indistinguishable)", async () => {
      const client = createRevokedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);

      const useCase = createUseCase({ repository });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("unknown client: returns recovery_failed (indistinguishable)", async () => {
      const repository = createStubClientRepository();

      const useCase = createUseCase({ repository });

      const result = await useCase.execute(validRecoveryRequest("unknown-client"));

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("no stored hash: returns recovery_failed", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      // Empty hash store — no hash stored for this client
      const recoveryHashStore = createStubRecoveryHashStore();

      const useCase = createUseCase({ repository, recoveryHashStore });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("recovery mode external_only: phrase recovery refused", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const config = RecoveryConfig.create({ recoveryMode: "external_only" });

      const useCase = createUseCase({ repository, recoveryHashStore, config });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("all failure responses have identical shape", async () => {
      const expectedFailure = { success: false, error: "recovery_failed" };

      // Active client
      const active = createActiveClient();
      const repo1 = createStubClientRepository(new Map([["alice-payment-service", active]]));
      const uc1 = createUseCase({ repository: repo1 });
      const r1 = await uc1.execute(validRecoveryRequest());
      expect(r1).toEqual(expectedFailure);

      // Revoked client
      const revoked = createRevokedClient();
      const repo2 = createStubClientRepository(new Map([["alice-payment-service", revoked]]));
      const uc2 = createUseCase({ repository: repo2 });
      const r2 = await uc2.execute(validRecoveryRequest());
      expect(r2).toEqual(expectedFailure);

      // Unknown client
      const repo3 = createStubClientRepository();
      const uc3 = createUseCase({ repository: repo3 });
      const r3 = await uc3.execute(validRecoveryRequest("unknown"));
      expect(r3).toEqual(expectedFailure);
    });
  });

  describe("early lockout enforcement (before Argon2)", () => {
    it("client already at max attempts: refused without calling Argon2", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const failedAttempts = new Map([["alice-payment-service", 3]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes, failedAttempts);

      let argon2Called = false;
      const spyArgon2Hasher: Argon2Hasher = {
        hash: async () => { argon2Called = true; return new Uint8Array(32); },
        verify: async () => { argon2Called = true; return true; },
      };

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: spyArgon2Hasher,
      });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
      expect(argon2Called).toBe(false);
    });

    it("client below max attempts: Argon2 verification proceeds", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const failedAttempts = new Map([["alice-payment-service", 2]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes, failedAttempts);

      let argon2Called = false;
      const spyArgon2Hasher: Argon2Hasher = {
        hash: async () => { argon2Called = true; return new Uint8Array(32); },
        verify: async () => { argon2Called = true; return true; },
      };

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: spyArgon2Hasher,
      });

      await useCase.execute(validRecoveryRequest());

      expect(argon2Called).toBe(true);
    });
  });

  describe("Argon2 concurrency limiting", () => {
    it("rejects recovery when concurrency limiter is full", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      // Limiter of 1, already full
      const limiter = new ConcurrencyLimiter(1);
      limiter.acquire(); // take the only slot

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        concurrencyLimiter: limiter,
      });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });

    it("allows recovery when concurrency limiter has slots available", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const limiter = new ConcurrencyLimiter(10);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        concurrencyLimiter: limiter,
      });

      const result = await useCase.execute(validRecoveryRequest());

      expect(result).toEqual({ success: true });
    });

    it("releases concurrency slot after verification completes", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const limiter = new ConcurrencyLimiter(1);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        concurrencyLimiter: limiter,
      });

      await useCase.execute(validRecoveryRequest());

      // After execution, the slot should be released
      expect(limiter.activeCount).toBe(0);
    });

    it("releases concurrency slot even on verification failure", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);

      const limiter = new ConcurrencyLimiter(1);

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: createNonMatchingArgon2Hasher(),
        concurrencyLimiter: limiter,
      });

      await useCase.execute(validRecoveryRequest("alice-payment-service", WRONG_WORDS));

      // Slot should be released even after failure
      expect(limiter.activeCount).toBe(0);
    });
  });

  describe("audit logging", () => {
    it("logs failed recovery attempt", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const hashes = new Map([["alice-payment-service", new Uint8Array(32).fill(0xab)]]);
      const recoveryHashStore = createStubRecoveryHashStore(hashes);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({
        repository,
        recoveryHashStore,
        argon2Hasher: createNonMatchingArgon2Hasher(),
        auditLogger,
      });

      await useCase.execute(validRecoveryRequest("alice-payment-service", WRONG_WORDS));

      const auditEvent = auditLogger.events.find((e) => e.eventType === "recovery_failed");
      expect(auditEvent).toBeDefined();
    });
  });
});
