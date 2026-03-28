// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { NapiTranscriptHasher } from "../../src/zk-verification/infrastructure/adapter/outgoing/napi-transcript-hasher.js";
import { VerifyProofUseCase } from "../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../src/zk-verification/domain/service/proof-verification-policy.js";
import {
  createAllStubs,
  createStubRateLimiter,
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
  validVerifyProofRequest,
  validChallengeInfo,
  activeCommitmentInfo,
  GENERATOR_G,
  GENERATOR_H,
  StubTranscriptHasher,
  StubProofEquationVerifier,
  StubElementValidator,
  StubCommitmentLookup,
  StubChallengeConsumer,
  StubFailedAttemptTracker,
} from "../helpers/verification-test-helpers.js";

describe("FIX 1 — Zero Challenge Guard", () => {
  describe("NapiTranscriptHasher failure behavior", () => {
    it("throws an error when the native module fails", () => {
      const failingModule = {
        hashTranscript: (): Buffer => {
          throw new Error("Native module segfault");
        },
      };
      const hasher = new NapiTranscriptHasher(failingModule);

      expect(() => hasher.hash(new Uint8Array(128))).toThrow(
        "Transcript hashing failed",
      );
    });

    it("does NOT return a zeroed array on native module failure", () => {
      const failingModule = {
        hashTranscript: (): Buffer => {
          throw new Error("Crash!");
        },
      };
      const hasher = new NapiTranscriptHasher(failingModule);

      let caught = false;
      try {
        hasher.hash(new Uint8Array(128));
      } catch {
        caught = true;
      }

      expect(caught).toBe(true);
    });

    it("returns valid result when native module succeeds", () => {
      const validResult = Buffer.alloc(32, 0x42);
      const workingModule = {
        hashTranscript: (): Buffer => validResult,
      };
      const hasher = new NapiTranscriptHasher(workingModule);

      const result = hasher.hash(new Uint8Array(128));
      expect(result).toEqual(new Uint8Array(validResult));
    });
  });

  describe("VerifyProofUseCase zero-challenge guard", () => {
    function createUseCaseWithHasher(hasher: StubTranscriptHasher) {
      const stubs = createAllStubs({ transcriptHasher: hasher });
      const policy = new ProofVerificationPolicy(stubs.elementValidator);
      const useCase = new VerifyProofUseCase(
        stubs.rateLimiter,
        stubs.challengeConsumer,
        stubs.commitmentLookup,
        policy,
        hasher,
        stubs.proofEquationVerifier,
        stubs.failedAttemptTracker,
        stubs.auditLogger,
        stubs.eventPublisher,
        stubs.clock,
        GENERATOR_G,
        GENERATOR_H,
      );
      return { useCase, stubs };
    }

    it("rejects proof when challenge scalar is all zeros", async () => {
      const zeroChallenge = new Uint8Array(32); // all zeros
      const hasher = new StubTranscriptHasher(zeroChallenge);
      const { useCase } = createUseCaseWithHasher(hasher);

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe("verification_refused");
      }
    });

    it("rejects zero challenge even if equation verifier would return true", async () => {
      const zeroChallenge = new Uint8Array(32); // all zeros
      const hasher = new StubTranscriptHasher(zeroChallenge);
      const stubs = createAllStubs({
        transcriptHasher: hasher,
        proofEquationVerifier: new StubProofEquationVerifier(true),
      });
      const policy = new ProofVerificationPolicy(stubs.elementValidator);
      const useCase = new VerifyProofUseCase(
        stubs.rateLimiter,
        stubs.challengeConsumer,
        stubs.commitmentLookup,
        policy,
        hasher,
        stubs.proofEquationVerifier,
        stubs.failedAttemptTracker,
        stubs.auditLogger,
        stubs.eventPublisher,
        stubs.clock,
        GENERATOR_G,
        GENERATOR_H,
      );

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe("verification_refused");
      }
    });

    it("allows non-zero challenge to proceed with normal verification", async () => {
      const nonZeroChallenge = new Uint8Array(32).fill(0x42);
      const hasher = new StubTranscriptHasher(nonZeroChallenge);
      const { useCase } = createUseCaseWithHasher(hasher);

      const result = await useCase.execute(validVerifyProofRequest());

      // With a valid non-zero challenge and stubbed equation verifier returning true,
      // verification should succeed
      expect(result.success).toBe(true);
    });
  });
});
