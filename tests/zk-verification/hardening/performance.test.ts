// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VerifyProofUseCase } from "../../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../../src/zk-verification/domain/service/proof-verification-policy.js";
import { BatchVerificationService } from "../../../src/zk-verification/domain/service/batch-verification-service.js";
import {
  createAllStubs,
  validVerifyProofRequest,
  validChallengeInfo,
  validProofBytes,
  GENERATOR_G,
  GENERATOR_H,
  StubProofEquationVerifier,
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

describe("Performance — Functional Correctness Under Batch/Load", () => {
  describe("Batch verification: 100 proofs verified", () => {
    it("should verify 100 valid proofs in a batch — all succeed", async () => {
      const { useCase } = createUseCase();
      const batchService = new BatchVerificationService(useCase);

      const requests = Array.from({ length: 100 }, (_, i) =>
        validVerifyProofRequest({ clientIdentifier: "alice-payment-service" }),
      );

      const results = await batchService.verifyBatch(requests);

      expect(results).toHaveLength(100);
      expect(results.every((r) => r.success)).toBe(true);
    });

    it("should report individual results for each proof in batch", async () => {
      const { useCase } = createUseCase();
      const batchService = new BatchVerificationService(useCase);

      const requests = Array.from({ length: 10 }, () => validVerifyProofRequest());
      const results = await batchService.verifyBatch(requests);

      results.forEach((result, idx) => {
        expect(result).toBeDefined();
        expect(typeof result.success).toBe("boolean");
      });
    });
  });

  describe("Mixed batch: valid + invalid proofs independently judged", () => {
    it("should accept valid proofs and reject invalid proofs in the same batch", async () => {
      // We alternate: even indices → valid (equation passes), odd indices → invalid
      let callIndex = 0;
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const originalVerify = proofEquationVerifier.verify.bind(proofEquationVerifier);

      // Create a custom verifier that alternates results
      const alternatingVerifier = {
        verifyCalls: 0,
        verify(): boolean {
          this.verifyCalls++;
          const isEven = (this.verifyCalls - 1) % 2 === 0;
          return isEven; // even = true, odd = false
        },
      };

      const stubs = createAllStubs({ proofEquationVerifier: alternatingVerifier as any });
      const policy = new ProofVerificationPolicy(stubs.elementValidator);
      const useCase = new VerifyProofUseCase(
        stubs.rateLimiter,
        stubs.challengeConsumer,
        stubs.commitmentLookup,
        policy,
        stubs.transcriptHasher,
        alternatingVerifier as any,
        stubs.failedAttemptTracker,
        stubs.auditLogger,
        stubs.eventPublisher,
        stubs.clock,
        GENERATOR_G,
        GENERATOR_H,
      );
      const batchService = new BatchVerificationService(useCase);

      const requests = Array.from({ length: 10 }, () => validVerifyProofRequest());

      // Execute sequentially to ensure deterministic alternation
      const results: Awaited<ReturnType<typeof useCase.execute>>[] = [];
      for (const req of requests) {
        results.push(await useCase.execute(req));
      }

      // Even indices succeed, odd indices fail
      expect(results[0]!.success).toBe(true);
      expect(results[1]!.success).toBe(false);
      expect(results[2]!.success).toBe(true);
      expect(results[3]!.success).toBe(false);
      expect(results[4]!.success).toBe(true);
    });

    it("should not let a single invalid proof affect other valid proofs", async () => {
      // 9 valid, 1 invalid (at index 5)
      let callCount = 0;
      const verifier = {
        verifyCalls: 0,
        verify(): boolean {
          this.verifyCalls++;
          return this.verifyCalls !== 6; // Only the 6th call fails
        },
      };

      const stubs = createAllStubs({ proofEquationVerifier: verifier as any });
      const policy = new ProofVerificationPolicy(stubs.elementValidator);
      const useCase = new VerifyProofUseCase(
        stubs.rateLimiter,
        stubs.challengeConsumer,
        stubs.commitmentLookup,
        policy,
        stubs.transcriptHasher,
        verifier as any,
        stubs.failedAttemptTracker,
        stubs.auditLogger,
        stubs.eventPublisher,
        stubs.clock,
        GENERATOR_G,
        GENERATOR_H,
      );

      const results: Awaited<ReturnType<typeof useCase.execute>>[] = [];
      for (let i = 0; i < 10; i++) {
        results.push(await useCase.execute(validVerifyProofRequest()));
      }

      // Only index 5 should fail
      const successCount = results.filter((r) => r.success).length;
      const failCount = results.filter((r) => !r.success).length;
      expect(successCount).toBe(9);
      expect(failCount).toBe(1);
      expect(results[5]!.success).toBe(false);
    });
  });

  describe("Sequential verification: 100 proofs in sequence", () => {
    it("should handle 100 sequential verifications without failure", async () => {
      const { useCase } = createUseCase();

      const results: Awaited<ReturnType<typeof useCase.execute>>[] = [];
      for (let i = 0; i < 100; i++) {
        results.push(await useCase.execute(validVerifyProofRequest()));
      }

      expect(results).toHaveLength(100);
      expect(results.every((r) => r.success)).toBe(true);
    });

    it("should maintain independent state across sequential verifications", async () => {
      const failedAttemptTracker = new (await import("../../helpers/verification-test-helpers.js")).StubFailedAttemptTracker();
      const { useCase } = createUseCase({ failedAttemptTracker });

      // 100 successful verifications → 100 resets, 0 failures
      for (let i = 0; i < 100; i++) {
        await useCase.execute(validVerifyProofRequest());
      }

      expect(failedAttemptTracker.resetCalls).toHaveLength(100);
      expect(failedAttemptTracker.recordedAttempts).toHaveLength(0);
    });
  });

  describe("Concurrent batch verification", () => {
    it("should handle 50 concurrent proof verifications", async () => {
      const { useCase } = createUseCase();

      const requests = Array.from({ length: 50 }, () => validVerifyProofRequest());
      const results = await Promise.all(
        requests.map((req) => useCase.execute(req)),
      );

      expect(results).toHaveLength(50);
      expect(results.every((r) => r.success)).toBe(true);
    });
  });
});
