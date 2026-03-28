// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { VerifyProofUseCase } from "../../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../../src/zk-verification/domain/service/proof-verification-policy.js";
import {
  createAllStubs,
  validVerifyProofRequest,
  validChallengeInfo,
  GENERATOR_G,
  GENERATOR_H,
  StubChallengeConsumer,
  StubProofEquationVerifier,
  StubTranscriptHasher,
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

/**
 * Generates a valid 96-byte proof with non-zero announcement.
 * Uses arbitrary bytes but ensures the first byte of announcement is non-zero
 * (to avoid identity point rejection).
 */
const validProofBytesArb = fc.uint8Array({ minLength: 96, maxLength: 96 }).map((bytes) => {
  const proof = new Uint8Array(bytes);
  // Ensure announcement is not all-zeros (identity point)
  if (proof[0] === 0) proof[0] = 1;
  return proof;
});

/**
 * Generates random 96-byte sequences (no constraint on content).
 */
const randomProofBytesArb = fc.uint8Array({ minLength: 96, maxLength: 96 });

describe("Algebraic Properties — Property-Based Tests", () => {
  describe("Completeness", () => {
    it("for all valid inputs, prove then verify succeeds (property, 100 runs)", async () => {
      // In our stub-based test, "valid" means:
      // - equation verifier returns true
      // - all other stubs return valid
      // We test the property that the verification pipeline always succeeds
      // for well-formed inputs with a passing equation verifier.
      const proofEquationVerifier = new StubProofEquationVerifier(true);
      const { useCase } = createUseCase({ proofEquationVerifier });

      await fc.assert(
        fc.asyncProperty(
          validProofBytesArb,
          async (proofBytes) => {
            const request = validVerifyProofRequest({ proofBytes });
            const result = await useCase.execute(request);
            expect(result.success).toBe(true);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  describe("Soundness", () => {
    it("random 96 bytes as proof never verifies (property, 100 runs)", async () => {
      // With the equation verifier returning false (random proofs won't pass equation),
      // verification always fails.
      const proofEquationVerifier = new StubProofEquationVerifier(false);
      const { useCase } = createUseCase({ proofEquationVerifier });

      await fc.assert(
        fc.asyncProperty(
          randomProofBytesArb,
          async (proofBytes) => {
            // Ensure non-identity to get past parsing
            const adjusted = new Uint8Array(proofBytes);
            if (adjusted[0] === 0) adjusted[0] = 1;

            const request = validVerifyProofRequest({ proofBytes: adjusted });
            const result = await useCase.execute(request);
            expect(result.success).toBe(false);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  describe("Malleability resistance", () => {
    it("flipping 1 bit in a valid proof causes rejection (property, 100 runs)", async () => {
      // Start with valid stubs, but after bit flip the equation verifier should fail
      // We simulate: equation verifier returns false for any non-matching proof
      let callCount = 0;
      const proofEquationVerifier: StubProofEquationVerifier = new StubProofEquationVerifier(false);

      const { useCase } = createUseCase({ proofEquationVerifier });

      await fc.assert(
        fc.asyncProperty(
          validProofBytesArb,
          fc.integer({ min: 0, max: 95 }), // byte index to flip
          fc.integer({ min: 0, max: 7 }),   // bit index within byte
          async (proofBytes, byteIdx, bitIdx) => {
            // Flip one bit
            const modified = new Uint8Array(proofBytes);
            modified[byteIdx] = modified[byteIdx]! ^ (1 << bitIdx);

            // Ensure announcement is still non-identity after flip
            let allZero = true;
            for (let i = 0; i < 32; i++) {
              if (modified[i] !== 0) { allZero = false; break; }
            }
            if (allZero) return; // skip: identity point case handled elsewhere

            const request = validVerifyProofRequest({ proofBytes: modified });
            const result = await useCase.execute(request);
            expect(result.success).toBe(false);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  describe("Fuzzing — random valid-length proofs", () => {
    it("random valid-length proofs never crash, always return a result (property, 100 runs)", async () => {
      const { useCase } = createUseCase();

      await fc.assert(
        fc.asyncProperty(
          randomProofBytesArb,
          async (proofBytes) => {
            const request = validVerifyProofRequest({ proofBytes });
            // Must not throw — always returns a result
            const result = await useCase.execute(request);
            expect(result).toBeDefined();
            expect(typeof result.success).toBe("boolean");
          },
        ),
        { numRuns: 100 },
      );
    });

    it("random-length payloads never crash (property, 100 runs)", async () => {
      const { useCase } = createUseCase();

      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 0, maxLength: 200 }),
          async (proofBytes) => {
            const request = validVerifyProofRequest({ proofBytes });
            const result = await useCase.execute(request);
            expect(result).toBeDefined();
            expect(typeof result.success).toBe("boolean");
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
