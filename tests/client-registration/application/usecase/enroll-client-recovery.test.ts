// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollClientUseCase } from "../../../../src/client-registration/application/usecase/enroll-client.usecase.js";
import { EnrollmentPolicy } from "../../../../src/client-registration/domain/service/enrollment-policy.js";
import { RecoveryPhraseGenerator } from "../../../../src/client-registration/domain/service/recovery-phrase-generator.js";
import { RecoveryVerifier } from "../../../../src/client-registration/domain/service/recovery-verifier.js";
import { RecoveryConfig } from "../../../../src/client-registration/domain/model/recovery-config.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "../../../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "../../../../src/client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import type { IdGenerator } from "../../../../src/client-registration/domain/port/outgoing/id-generator.js";
import type { RecoveryHashStore } from "../../../../src/client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { Bip39WordlistProvider } from "../../../../src/client-registration/domain/model/bip39-wordlist.js";
import type { SecureRandomProvider } from "../../../../src/client-registration/domain/port/outgoing/secure-random-provider.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { StubArgon2Hasher } from "../../../../src/client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";
import { StubBip39WordlistProvider } from "../../../../src/client-registration/infrastructure/adapter/outgoing/stub-bip39-wordlist-provider.js";
import { InMemoryRecoveryHashStore } from "../../../../src/client-registration/infrastructure/adapter/outgoing/in-memory-recovery-hash-store.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createNoopRateLimiter,
  validRequest,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Stubs ---

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

function createStubIdGenerator(): IdGenerator {
  return { generate: () => ClientId.fromBytes(new Uint8Array(16).fill(99)) };
}

function createStubClientRepository(
  existingClients: Map<string, Client> = new Map(),
): ClientRepository & { savedClients: Client[] } {
  const savedClients: Client[] = [];
  return {
    savedClients,
    save: async (client: Client) => {
      savedClients.push(client);
      existingClients.set(client.identifier, client);
    },
    findByIdentifier: async (identifier: string) => existingClients.get(identifier) ?? null,
    existsByIdentifier: async (identifier: string) => existingClients.has(identifier),
  };
}

function createDeterministicRandom(): SecureRandomProvider {
  let index = 0;
  return {
    randomIndex(max: number): number {
      return (index++) % max;
    },
  };
}

function createEnrollUseCaseWithRecovery(overrides: {
  repository?: ClientRepository;
  recoveryHashStore?: RecoveryHashStore;
  recoveryConfig?: RecoveryConfig;
} = {}) {
  const repository = overrides.repository ?? createStubClientRepository();
  const recoveryConfig = overrides.recoveryConfig ?? RecoveryConfig.defaults();
  const argon2Hasher = new StubArgon2Hasher();
  const wordlistProvider = new StubBip39WordlistProvider();
  const secureRandom = createDeterministicRandom();
  const phraseGenerator = new RecoveryPhraseGenerator(wordlistProvider, secureRandom);
  const recoveryVerifier = new RecoveryVerifier(argon2Hasher);
  const recoveryHashStore = overrides.recoveryHashStore ?? new InMemoryRecoveryHashStore();

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
    phraseGenerator,
    recoveryVerifier,
    recoveryHashStore,
    recoveryConfig,
  );

  return { useCase, repository, recoveryHashStore };
}

describe("EnrollClientUseCase — Recovery Integration", () => {
  it("new enrollment returns recovery words in response", async () => {
    const { useCase } = createEnrollUseCaseWithRecovery();

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.recoveryWords).toBeDefined();
      expect(result.recoveryWords!.length).toBe(12);
      // Each word should be from BIP-39 wordlist
      for (const word of result.recoveryWords!) {
        expect(word).toMatch(/^[a-z]+$/);
      }
    }
  });

  it("recovery hash is stored after enrollment", async () => {
    const recoveryHashStore = new InMemoryRecoveryHashStore();
    const { useCase } = createEnrollUseCaseWithRecovery({ recoveryHashStore });

    await useCase.execute(validRequest());

    const storedHash = await recoveryHashStore.getHash("test-client-1");
    expect(storedHash).not.toBeNull();
    expect(storedHash!.length).toBe(32);
  });

  it("idempotent re-enrollment does NOT return recovery words", async () => {
    const { useCase } = createEnrollUseCaseWithRecovery();

    const request = validRequest();
    await useCase.execute(request);

    // Second enrollment with same commitment (idempotent)
    const result2 = await useCase.execute(request);

    expect(result2.success).toBe(true);
    if (result2.success) {
      expect(result2.recoveryWords).toBeUndefined();
    }
  });

  it("enrollment with external_only mode does NOT generate recovery words", async () => {
    const config = RecoveryConfig.create({ recoveryMode: "external_only" });
    const { useCase } = createEnrollUseCaseWithRecovery({ recoveryConfig: config });

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.recoveryWords).toBeUndefined();
    }
  });

  it("enrollment with phrase_only mode generates recovery words", async () => {
    const config = RecoveryConfig.create({ recoveryMode: "phrase_only" });
    const { useCase } = createEnrollUseCaseWithRecovery({ recoveryConfig: config });

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.recoveryWords).toBeDefined();
      expect(result.recoveryWords!.length).toBe(12);
    }
  });

  it("24-word configuration produces 24 recovery words", async () => {
    const config = RecoveryConfig.create({ wordCount: 24 });
    const { useCase } = createEnrollUseCaseWithRecovery({ recoveryConfig: config });

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.recoveryWords).toBeDefined();
      expect(result.recoveryWords!.length).toBe(24);
    }
  });

  it("failed enrollment does NOT generate recovery words", async () => {
    const failingPolicy = new EnrollmentPolicy(
      { isCanonical: () => false, isValidGroupElement: () => true, isIdentityElement: () => false },
      { verify: () => true },
    );

    const argon2Hasher = new StubArgon2Hasher();
    const phraseGenerator = new RecoveryPhraseGenerator(new StubBip39WordlistProvider(), createDeterministicRandom());
    const recoveryVerifier = new RecoveryVerifier(argon2Hasher);
    const recoveryHashStore = new InMemoryRecoveryHashStore();

    const useCase = new EnrollClientUseCase(
      failingPolicy,
      createStubClientRepository(),
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createNoopRateLimiter(),
      phraseGenerator,
      recoveryVerifier,
      recoveryHashStore,
      RecoveryConfig.defaults(),
    );

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(false);
    // No hash should have been stored
    const storedHash = await recoveryHashStore.getHash("test-client-1");
    expect(storedHash).toBeNull();
  });
});
