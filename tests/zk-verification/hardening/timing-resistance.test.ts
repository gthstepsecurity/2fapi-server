// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VerifyProofUseCase } from "../../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../../src/zk-verification/domain/service/proof-verification-policy.js";
import {
  createAllStubs,
  validVerifyProofRequest,
  validChallengeInfo,
  activeCommitmentInfo,
  validProofBytes,
  GENERATOR_G,
  GENERATOR_H,
  StubChallengeConsumer,
  StubCommitmentLookup,
  StubElementValidator,
  StubProofEquationVerifier,
  StubTranscriptHasher,
  StubFailedAttemptTracker,
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
  createStubRateLimiter,
  type AllStubs,
} from "../../helpers/verification-test-helpers.js";

function createUseCase(overrides: Partial<AllStubs> = {}) {
  const stubs = createAllStubs(overrides);
  const policy = new ProofVerificationPolicy(stubs.elementValidator);
  const useCase = new VerifyProofUseCase(
    stubs.rateLimiter,
    stubs.challengeConsumer,
    stubs.commitmentLookup,
    policy,
    stubs.transcriptHasher,
    stubs.proofEquationVerifier,
    stubs.failedAttemptTracker,
    stubs.auditLogger,
    stubs.eventPublisher,
    stubs.clock,
    GENERATOR_G,
    GENERATOR_H,
  );
  return { useCase, ...stubs };
}

describe("Timing Side-Channel Resistance — Behavioral Tests", () => {
  describe("All verification error paths execute dummy operations", () => {
    it("should call proof equation verifier even when challenge is invalid", async () => {
      const challengeConsumer = new StubChallengeConsumer(null);
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ challengeConsumer, proofEquationVerifier });

      const result = await useCase.execute(validVerifyProofRequest());

      // Verification fails (bad challenge), but equation verifier WAS called
      expect(result.success).toBe(false);
      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });

    it("should call proof equation verifier even when client is unknown", async () => {
      const commitmentLookup = new StubCommitmentLookup(null);
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ commitmentLookup, proofEquationVerifier });

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });

    it("should call proof equation verifier even when channel binding mismatches", async () => {
      const challengeConsumer = new StubChallengeConsumer(
        validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xff) }),
      );
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ challengeConsumer, proofEquationVerifier });

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });

    it("should call proof equation verifier even when domain tag is wrong", async () => {
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ proofEquationVerifier });

      const result = await useCase.execute(
        validVerifyProofRequest({ domainSeparationTag: "wrong-tag" }),
      );

      expect(result.success).toBe(false);
      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });

    it("should call proof equation verifier even when client is revoked", async () => {
      const commitmentLookup = new StubCommitmentLookup({
        commitment: new Uint8Array(32).fill(0xaa),
        clientStatus: "revoked",
      });
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ commitmentLookup, proofEquationVerifier });

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });
  });

  describe("Unknown client does not short-circuit", () => {
    it("should perform commitment lookup even when challenge is consumed", async () => {
      const challengeConsumer = new StubChallengeConsumer(null);
      const commitmentLookup = new StubCommitmentLookup(activeCommitmentInfo());
      let lookupCalled = false;
      const originalFind = commitmentLookup.findByClientIdentifier.bind(commitmentLookup);
      commitmentLookup.findByClientIdentifier = async (id: string) => {
        lookupCalled = true;
        return originalFind(id);
      };
      const { useCase } = createUseCase({ challengeConsumer, commitmentLookup });

      await useCase.execute(validVerifyProofRequest());

      expect(lookupCalled).toBe(true);
    });

    it("should perform transcript hashing for unknown client (dummy path)", async () => {
      const commitmentLookup = new StubCommitmentLookup(null);
      const transcriptHasher = new StubTranscriptHasher();
      let hashCalled = false;
      const originalHash = transcriptHasher.hash.bind(transcriptHasher);
      transcriptHasher.hash = (bytes: Uint8Array) => {
        hashCalled = true;
        return originalHash(bytes);
      };
      const { useCase } = createUseCase({ commitmentLookup, transcriptHasher });

      await useCase.execute(validVerifyProofRequest());

      expect(hashCalled).toBe(true);
    });
  });

  describe("Channel binding mismatch does not short-circuit", () => {
    it("should still call transcript hasher when channel binding mismatches", async () => {
      const challengeConsumer = new StubChallengeConsumer(
        validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xff) }),
      );
      const transcriptHasher = new StubTranscriptHasher();
      let hashCalled = false;
      const originalHash = transcriptHasher.hash.bind(transcriptHasher);
      transcriptHasher.hash = (bytes: Uint8Array) => {
        hashCalled = true;
        return originalHash(bytes);
      };
      const { useCase } = createUseCase({ challengeConsumer, transcriptHasher });

      await useCase.execute(validVerifyProofRequest());

      expect(hashCalled).toBe(true);
    });

    it("should still call equation verifier when channel binding mismatches", async () => {
      const challengeConsumer = new StubChallengeConsumer(
        validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xff) }),
      );
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ challengeConsumer, proofEquationVerifier });

      await useCase.execute(validVerifyProofRequest());

      expect(proofEquationVerifier.verifyCalls).toBe(1);
    });
  });

  describe("Five-class timing equivalence (behavioral)", () => {
    /**
     * We verify that ALL five error classes exercise the same set of operations:
     * commitment lookup, transcript hash, proof equation verify.
     * This is a behavioral (not statistical) constant-time test.
     */
    interface OperationCounts {
      lookupCalled: boolean;
      hashCalled: boolean;
      equationCalled: boolean;
    }

    async function measureOperations(overrides: Partial<AllStubs>, requestOverrides: Partial<Parameters<typeof validVerifyProofRequest>[0]> = {}): Promise<OperationCounts> {
      const commitmentLookup = (overrides.commitmentLookup as StubCommitmentLookup | undefined) ?? new StubCommitmentLookup(activeCommitmentInfo());
      let lookupCalled = false;
      const originalFind = commitmentLookup.findByClientIdentifier.bind(commitmentLookup);
      commitmentLookup.findByClientIdentifier = async (id: string) => {
        lookupCalled = true;
        return originalFind(id);
      };

      const transcriptHasher = (overrides.transcriptHasher as StubTranscriptHasher | undefined) ?? new StubTranscriptHasher();
      let hashCalled = false;
      const originalHash = transcriptHasher.hash.bind(transcriptHasher);
      transcriptHasher.hash = (bytes: Uint8Array) => {
        hashCalled = true;
        return originalHash(bytes);
      };

      const proofEquationVerifier = (overrides.proofEquationVerifier as StubProofEquationVerifier | undefined) ?? new StubProofEquationVerifier(true);

      const { useCase } = createUseCase({
        ...overrides,
        commitmentLookup,
        transcriptHasher,
        proofEquationVerifier,
      });

      await useCase.execute(validVerifyProofRequest(requestOverrides));

      return {
        lookupCalled,
        hashCalled,
        equationCalled: proofEquationVerifier.verifyCalls > 0,
      };
    }

    it("Class A (success): all operations called", async () => {
      const ops = await measureOperations({});
      expect(ops.lookupCalled).toBe(true);
      expect(ops.hashCalled).toBe(true);
      expect(ops.equationCalled).toBe(true);
    });

    it("Class B (unknown client): all operations called", async () => {
      const ops = await measureOperations({
        commitmentLookup: new StubCommitmentLookup(null),
      });
      expect(ops.lookupCalled).toBe(true);
      expect(ops.hashCalled).toBe(true);
      expect(ops.equationCalled).toBe(true);
    });

    it("Class C (expired challenge): all operations called", async () => {
      const ops = await measureOperations({
        challengeConsumer: new StubChallengeConsumer(null),
      });
      expect(ops.lookupCalled).toBe(true);
      expect(ops.hashCalled).toBe(true);
      expect(ops.equationCalled).toBe(true);
    });

    it("Class D (wrong proof equation): all operations called", async () => {
      const ops = await measureOperations({
        proofEquationVerifier: new StubProofEquationVerifier(false),
      });
      expect(ops.lookupCalled).toBe(true);
      expect(ops.hashCalled).toBe(true);
      expect(ops.equationCalled).toBe(true);
    });

    it("Class E (wrong channel binding): all operations called", async () => {
      const ops = await measureOperations({
        challengeConsumer: new StubChallengeConsumer(
          validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xff) }),
        ),
      });
      expect(ops.lookupCalled).toBe(true);
      expect(ops.hashCalled).toBe(true);
      expect(ops.equationCalled).toBe(true);
    });
  });
});
