// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Client } from "../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../src/client-registration/domain/model/commitment.js";
import { RecoveryConfig } from "../../src/client-registration/domain/model/recovery-config.js";
import { RecoveryPhraseGenerator } from "../../src/client-registration/domain/service/recovery-phrase-generator.js";
import { RecoveryVerifier } from "../../src/client-registration/domain/service/recovery-verifier.js";
import { RecoverViaPhraseUseCase } from "../../src/client-registration/application/usecase/recover-via-phrase.usecase.js";
import { ReactivateViaExternalUseCase } from "../../src/client-registration/application/usecase/reactivate-via-external.usecase.js";
import { InMemoryRecoveryHashStore } from "../../src/client-registration/infrastructure/adapter/outgoing/in-memory-recovery-hash-store.js";
import { StubArgon2Hasher } from "../../src/client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";
import { StubBip39WordlistProvider } from "../../src/client-registration/infrastructure/adapter/outgoing/stub-bip39-wordlist-provider.js";
import { CryptoSecureRandomProvider } from "../../src/client-registration/infrastructure/adapter/outgoing/crypto-secure-random-provider.js";
import { InMemoryClientRepository } from "../../src/client-registration/infrastructure/adapter/outgoing/in-memory-client-repository.js";
import type { ClientRepository } from "../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { AdminAuthenticator } from "../../src/client-registration/domain/port/outgoing/admin-authenticator.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../helpers/enrollment-test-helpers.js";

// --- Shared Test Setup ---

function createStubTokenInvalidator() {
  return {
    invalidatedClients: [] as string[],
    invalidateAllForClient: async (id: string) => {
      createStubTokenInvalidator.last?.invalidatedClients.push(id);
    },
  };
}
createStubTokenInvalidator.last = null as ReturnType<typeof createStubTokenInvalidator> | null;

function createTokenInvalidator() {
  const inv = {
    invalidatedClients: [] as string[],
    invalidateAllForClient: async (id: string) => {
      inv.invalidatedClients.push(id);
    },
  };
  return inv;
}

function createChallengeInvalidator() {
  const inv = {
    invalidatedClients: [] as string[],
    invalidateAllForClient: async (id: string) => {
      inv.invalidatedClients.push(id);
    },
  };
  return inv;
}

function createAdminAuthenticator(validAdmins: Set<string> = new Set(["bob-admin-id"])): AdminAuthenticator {
  return {
    isValidAdmin: async (adminIdentity: string) => validAdmins.has(adminIdentity),
  };
}

/**
 * Sets up the full enrollment + recovery stack.
 * Enrolls a client, generates recovery words, stores hash, suspends client.
 */
async function setupSuspendedClientWithRecoveryPhrase(config?: RecoveryConfig) {
  const recoveryConfig = config ?? RecoveryConfig.defaults();
  const argon2Hasher = new StubArgon2Hasher();
  const wordlistProvider = new StubBip39WordlistProvider();
  const secureRandom = new CryptoSecureRandomProvider();
  const phraseGenerator = new RecoveryPhraseGenerator(wordlistProvider, secureRandom);
  const recoveryVerifier = new RecoveryVerifier(argon2Hasher);
  const recoveryHashStore = new InMemoryRecoveryHashStore();

  // 1. Enroll client
  const clientId = ClientId.fromBytes(new Uint8Array(16).fill(7));
  const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0xab));
  const client = Client.register(clientId, "alice-payment-service", commitment);

  // Save to repository
  const repository = new InMemoryClientRepository();
  await repository.save(client);

  // 2. Generate recovery words
  const phrase = phraseGenerator.generate(recoveryConfig.wordCount);
  const words = phrase.toDisplayString().split(" ");

  // 3. Hash recovery words and store hash
  const hash = await recoveryVerifier.deriveHash(words, "alice-payment-service", recoveryConfig);
  await recoveryHashStore.storeHash("alice-payment-service", hash);

  // 4. Suspend client
  const suspendedClient = client.suspend();
  await repository.update(suspendedClient);

  return {
    repository,
    recoveryHashStore,
    argon2Hasher,
    recoveryConfig,
    words,
    phraseGenerator,
    recoveryVerifier,
  };
}

describe("Recovery — Acceptance Tests", () => {
  describe("Full flow: enroll → get words → suspend → recover with words → new commitment works", () => {
    it("suspended client recovers with correct words and gets active status with new commitment", async () => {
      const {
        repository,
        recoveryHashStore,
        argon2Hasher,
        recoveryConfig,
        words,
      } = await setupSuspendedClientWithRecoveryPhrase();

      const auditLogger = createCapturingAuditLogger();
      const eventPublisher = createCapturingEventPublisher();

      const useCase = new RecoverViaPhraseUseCase(
        repository,
        recoveryHashStore,
        argon2Hasher,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        auditLogger,
        eventPublisher,
        recoveryConfig,
      );

      // Client is suspended before recovery
      const beforeRecovery = await repository.findByIdentifier("alice-payment-service");
      expect(beforeRecovery!.status).toBe("suspended");

      // Recover with correct words
      const newCommitmentBytes = new Uint8Array(32).fill(0xdd);
      const result = await useCase.execute({
        clientIdentifier: "alice-payment-service",
        words,
        newCommitmentBytes,
        newCommitmentProofBytes: new Uint8Array(96).fill(0xee),
      });

      expect(result.success).toBe(true);

      // Client is now active with new commitment
      const afterRecovery = await repository.findByIdentifier("alice-payment-service");
      expect(afterRecovery!.status).toBe("active");
      expect(afterRecovery!.commitment.toBytes()).toEqual(newCommitmentBytes);
      expect(afterRecovery!.commitmentVersion).toBe(2);

      // ClientRecovered event published
      expect(eventPublisher.events.length).toBe(1);
      expect(eventPublisher.events[0]!.eventType).toBe("ClientRecovered");

      // Audit logged
      const recoveredAudit = auditLogger.events.find((e) => e.eventType === "client_recovered");
      expect(recoveredAudit).toBeDefined();
    });
  });

  describe("Full flow: enroll → suspend → admin reactivate → new commitment", () => {
    it("admin reactivates suspended client with new commitment", async () => {
      const {
        repository,
        recoveryHashStore,
      } = await setupSuspendedClientWithRecoveryPhrase();

      const auditLogger = createCapturingAuditLogger();
      const eventPublisher = createCapturingEventPublisher();

      const useCase = new ReactivateViaExternalUseCase(
        createAdminAuthenticator(),
        repository,
        recoveryHashStore,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        auditLogger,
        eventPublisher,
        { verify: () => true },
      );

      const newCommitmentBytes = new Uint8Array(32).fill(0xee);
      const result = await useCase.execute({
        clientIdentifier: "alice-payment-service",
        adminIdentity: "bob-admin-id",
        newCommitmentBytes,
        newCommitmentProofBytes: new Uint8Array(96).fill(0xff),
      });

      expect(result.success).toBe(true);

      // Client is now active with new commitment
      const client = await repository.findByIdentifier("alice-payment-service");
      expect(client!.status).toBe("active");
      expect(client!.commitment.toBytes()).toEqual(newCommitmentBytes);

      // ClientReactivated event published
      expect(eventPublisher.events.length).toBe(1);
      expect(eventPublisher.events[0]!.eventType).toBe("ClientReactivated");

      // Audit logged with admin identity
      const auditEvent = auditLogger.events.find((e) => e.eventType === "client_reactivated");
      expect(auditEvent).toBeDefined();
      expect(auditEvent!.metadata).toEqual(
        expect.objectContaining({ adminIdentity: "bob-admin-id" }),
      );
    });
  });

  describe("Wrong words → failed → 3 attempts → locked → admin only", () => {
    it("3 wrong attempts lock recovery, then admin can reactivate", async () => {
      const {
        repository,
        recoveryHashStore,
        argon2Hasher,
        recoveryConfig,
      } = await setupSuspendedClientWithRecoveryPhrase();

      const phraseUseCase = new RecoverViaPhraseUseCase(
        repository,
        recoveryHashStore,
        argon2Hasher,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        createCapturingAuditLogger(),
        createCapturingEventPublisher(),
        recoveryConfig,
      );

      const wrongWords = [
        "zoo", "zone", "zero", "year",
        "wrong", "write", "world", "wonder",
        "witness", "window", "winter", "wild",
      ];

      // 3 failed attempts
      for (let i = 0; i < 3; i++) {
        const result = await phraseUseCase.execute({
          clientIdentifier: "alice-payment-service",
          words: wrongWords,
          newCommitmentBytes: new Uint8Array(32).fill(0xdd),
          newCommitmentProofBytes: new Uint8Array(96).fill(0xee),
        });
        expect(result.success).toBe(false);
      }

      // Client is still suspended
      const lockedClient = await repository.findByIdentifier("alice-payment-service");
      expect(lockedClient!.status).toBe("suspended");

      // Now admin reactivates
      const adminUseCase = new ReactivateViaExternalUseCase(
        createAdminAuthenticator(),
        repository,
        recoveryHashStore,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        createCapturingAuditLogger(),
        createCapturingEventPublisher(),
        { verify: () => true },
      );

      const adminResult = await adminUseCase.execute({
        clientIdentifier: "alice-payment-service",
        adminIdentity: "bob-admin-id",
        newCommitmentBytes: new Uint8Array(32).fill(0xff),
        newCommitmentProofBytes: new Uint8Array(96).fill(0xaa),
      });

      expect(adminResult.success).toBe(true);

      const reactivatedClient = await repository.findByIdentifier("alice-payment-service");
      expect(reactivatedClient!.status).toBe("active");
      expect(reactivatedClient!.commitment.toBytes()).toEqual(new Uint8Array(32).fill(0xff));
    });
  });

  describe("Recovery mode configuration", () => {
    it("external_only mode refuses phrase recovery", async () => {
      const config = RecoveryConfig.create({ recoveryMode: "external_only" });
      const {
        repository,
        recoveryHashStore,
        argon2Hasher,
        words,
      } = await setupSuspendedClientWithRecoveryPhrase(config);

      const useCase = new RecoverViaPhraseUseCase(
        repository,
        recoveryHashStore,
        argon2Hasher,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        createCapturingAuditLogger(),
        createCapturingEventPublisher(),
        config,
      );

      const result = await useCase.execute({
        clientIdentifier: "alice-payment-service",
        words,
        newCommitmentBytes: new Uint8Array(32).fill(0xdd),
        newCommitmentProofBytes: new Uint8Array(96).fill(0xee),
      });

      expect(result).toEqual({ success: false, error: "recovery_failed" });
    });
  });

  describe("Security: indistinguishable responses", () => {
    it("all failure responses have identical shape regardless of reason", async () => {
      const {
        repository,
        recoveryHashStore,
        argon2Hasher,
        recoveryConfig,
      } = await setupSuspendedClientWithRecoveryPhrase();

      const useCase = new RecoverViaPhraseUseCase(
        repository,
        recoveryHashStore,
        argon2Hasher,
        createTokenInvalidator(),
        createChallengeInvalidator(),
        createCapturingAuditLogger(),
        createCapturingEventPublisher(),
        recoveryConfig,
      );

      const expectedFailure = { success: false, error: "recovery_failed" };

      // Wrong words
      const r1 = await useCase.execute({
        clientIdentifier: "alice-payment-service",
        words: ["zoo", "zone", "zero", "year", "wrong", "write", "world", "wonder", "witness", "window", "winter", "wild"],
        newCommitmentBytes: new Uint8Array(32).fill(0xdd),
        newCommitmentProofBytes: new Uint8Array(96).fill(0xee),
      });
      expect(r1).toEqual(expectedFailure);

      // Unknown client
      const r2 = await useCase.execute({
        clientIdentifier: "unknown-client",
        words: ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"],
        newCommitmentBytes: new Uint8Array(32).fill(0xdd),
        newCommitmentProofBytes: new Uint8Array(96).fill(0xee),
      });
      expect(r2).toEqual(expectedFailure);
    });
  });
});
