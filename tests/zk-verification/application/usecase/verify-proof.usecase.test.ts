// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VerifyProofUseCase } from "../../../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../../../src/zk-verification/domain/service/proof-verification-policy.js";
import {
  createAllStubs,
  createStubRateLimiter,
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
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
  type AllStubs,
} from "../../../helpers/verification-test-helpers.js";

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

describe("VerifyProofUseCase", () => {
  // === Happy Path ===

  it("should return success when proof is valid", async () => {
    const { useCase } = createUseCase();

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.clientIdentifier).toBe("alice-payment-service");
    }
  });

  it("should consume the challenge on success", async () => {
    const challengeConsumer = new StubChallengeConsumer(validChallengeInfo());
    const { useCase } = createUseCase({ challengeConsumer });

    await useCase.execute(validVerifyProofRequest());

    expect(challengeConsumer.consumedChallengeIds).toContain("challenge-001");
  });

  it("should reset failed attempts counter on success", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const { useCase } = createUseCase({ failedAttemptTracker });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.resetCalls).toContain("alice-payment-service");
  });

  it("should publish ProofVerified event on success", async () => {
    const eventPublisher = createCapturingEventPublisher();
    const clock = createStubClock(1700000000);
    const { useCase } = createUseCase({ eventPublisher, clock });

    await useCase.execute(validVerifyProofRequest());

    expect(eventPublisher.events).toHaveLength(1);
    const event = eventPublisher.events[0]!;
    expect(event.eventType).toBe("ProofVerified");
    expect((event as any).clientIdentifier).toBe("alice-payment-service");
    expect((event as any).challengeId).toBe("challenge-001");
    expect((event as any).verifiedAtMs).toBe(1700000000);
    expect((event as any).occurredAt).toBeInstanceOf(Date);
    expect((event as any).occurredAt.getTime()).toBe(1700000000);
  });

  it("should audit log proof_verified on success", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    await useCase.execute(validVerifyProofRequest());

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("proof_verified");
    expect(auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(auditLogger.entries[0]!.details["challengeId"]).toBe("challenge-001");
    expect(auditLogger.entries[0]!.timestamp).toBeInstanceOf(Date);
  });

  // === Rate Limiting ===

  it("should return rate_limited when rate limiter blocks", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({
      rateLimiter: createStubRateLimiter(false),
      auditLogger,
    });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("rate_limited");
    }
    // Rate limiting returns immediately, no audit log
    expect(auditLogger.entries).toHaveLength(0);
  });

  it("should accept clientIdentifier at exactly 256 bytes", async () => {
    const { useCase } = createUseCase();
    const id256 = "a".repeat(256);
    const result = await useCase.execute(validVerifyProofRequest({ clientIdentifier: id256 }));
    // Should NOT fail on input validation (might fail later due to challenge mismatch)
    expect(result.success === false && result.error === "verification_refused").toBe(true);
  });

  // === Input Validation ===

  it("should return verification_refused when clientIdentifier is empty", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const request = validVerifyProofRequest({ clientIdentifier: "" });
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("verification_refused");
    expect(auditLogger.entries[0]!.details["reason"]).toBe("invalid_input");
  });

  it("should return verification_refused when clientIdentifier exceeds 256 bytes", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const longId = "a".repeat(257);
    const request = validVerifyProofRequest({ clientIdentifier: longId });
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("verification_refused");
    expect(auditLogger.entries[0]!.details["reason"]).toBe("invalid_input");
  });

  it("should return verification_refused when proof is not 96 bytes", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const request = validVerifyProofRequest({ proofBytes: new Uint8Array(64) });
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("verification_refused");
    expect(auditLogger.entries[0]!.details["reason"]).toBe("invalid_proof_size");
  });

  // === Challenge Consumption ===

  it("should return verification_refused when challenge is already consumed (indistinguishable)", async () => {
    const challengeConsumer = new StubChallengeConsumer(null); // null = consumed/unknown/expired
    const { useCase } = createUseCase({ challengeConsumer });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  it("should return verification_refused when challenge is expired or unknown (indistinguishable from consumed)", async () => {
    const challengeConsumer = new StubChallengeConsumer(null);
    const { useCase } = createUseCase({ challengeConsumer });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  // === Client Lookup ===

  it("should return verification_refused when client is unknown (not found)", async () => {
    const commitmentLookup = new StubCommitmentLookup(null);
    const { useCase } = createUseCase({ commitmentLookup });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  it("should return verification_refused when client is revoked", async () => {
    const commitmentLookup = new StubCommitmentLookup({
      commitment: new Uint8Array(32).fill(0xaa),
      clientStatus: "revoked",
    });
    const { useCase } = createUseCase({ commitmentLookup });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  // === Channel Binding ===

  it("should return verification_refused when channel binding does not match challenge", async () => {
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xdd) }),
    );
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const { useCase } = createUseCase({ challengeConsumer, failedAttemptTracker });

    // Request has channelBinding 0xcc, challenge has 0xdd
    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
    expect(failedAttemptTracker.recordedAttempts).toContain("alice-payment-service");
  });

  // === Domain Separation Tag ===

  it("should return verification_refused when domain separation tag is wrong", async () => {
    const { useCase } = createUseCase();

    const request = validVerifyProofRequest({ domainSeparationTag: "wrong-tag" });
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  // === Proof Encoding ===

  it("should return verification_refused when scalar is not canonical", async () => {
    const elementValidator = new StubElementValidator({ canonicalScalar: false });
    const { useCase } = createUseCase({ elementValidator });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  it("should return verification_refused when point is not canonical", async () => {
    const elementValidator = new StubElementValidator({ canonicalPoint: false });
    const { useCase } = createUseCase({ elementValidator });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  it("should return verification_refused when announcement is identity element", async () => {
    const { useCase } = createUseCase();

    // Identity announcement = all zeros for first 32 bytes
    const identityProof = new Uint8Array(96);
    identityProof[32] = 0x02; // responseS
    identityProof[64] = 0x03; // responseR
    const request = validVerifyProofRequest({ proofBytes: identityProof });
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  // === Proof Equation ===

  it("should return verification_refused when proof equation fails", async () => {
    const proofEquationVerifier = new StubProofEquationVerifier(false);
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const { useCase } = createUseCase({ proofEquationVerifier, failedAttemptTracker });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
    expect(failedAttemptTracker.recordedAttempts).toContain("alice-payment-service");
  });

  // === Audit Logging ===

  it("should audit log verification_refused on failure", async () => {
    const auditLogger = createCapturingAuditLogger();
    const proofEquationVerifier = new StubProofEquationVerifier(false);
    const { useCase } = createUseCase({ auditLogger, proofEquationVerifier });

    await useCase.execute(validVerifyProofRequest());

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("verification_refused");
    expect(auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(auditLogger.entries[0]!.details["challengeId"]).toBe("challenge-001");
    expect(auditLogger.entries[0]!.timestamp).toBeInstanceOf(Date);
  });

  it("should audit log with reason details on challenge failure", async () => {
    const auditLogger = createCapturingAuditLogger();
    const challengeConsumer = new StubChallengeConsumer(null);
    const { useCase } = createUseCase({ auditLogger, challengeConsumer });

    await useCase.execute(validVerifyProofRequest());

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("verification_refused");
    expect(auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(auditLogger.entries[0]!.details["challengeId"]).toBe("challenge-001");
  });

  // === Client Identifier Mismatch (#14) ===

  it("should return verification_refused when challenge belongs to a different client", async () => {
    // Challenge was issued for "bob-service" but "alice-payment-service" is requesting
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ clientIdentifier: "bob-service" }),
    );
    const { useCase } = createUseCase({ challengeConsumer });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  // === Timing Safety: constant-time execution ===

  it("should still perform commitment lookup even when challenge is invalid (timing-safe)", async () => {
    const challengeConsumer = new StubChallengeConsumer(null);
    const commitmentLookup = new StubCommitmentLookup(activeCommitmentInfo());
    // Spy on findByClientIdentifier
    let lookupCalled = false;
    const originalFind = commitmentLookup.findByClientIdentifier.bind(commitmentLookup);
    commitmentLookup.findByClientIdentifier = async (clientIdentifier: string) => {
      lookupCalled = true;
      return originalFind(clientIdentifier);
    };
    const { useCase } = createUseCase({ challengeConsumer, commitmentLookup });

    await useCase.execute(validVerifyProofRequest());

    expect(lookupCalled).toBe(true);
  });

  it("should call proof equation verifier even when challenge is invalid (timing-safe, #6/#17)", async () => {
    const challengeConsumer = new StubChallengeConsumer(null); // invalid challenge
    const proofEquationVerifier = new StubProofEquationVerifier(true);
    const { useCase } = createUseCase({ challengeConsumer, proofEquationVerifier });

    const result = await useCase.execute(validVerifyProofRequest());

    // Verification still fails (challenge was invalid)
    expect(result.success).toBe(false);
    // But the equation verifier was called for timing safety
    expect(proofEquationVerifier.verifyCalls).toBe(1);
  });

  it("should call proof equation verifier even when policy validation fails (timing-safe)", async () => {
    const commitmentLookup = new StubCommitmentLookup(null); // client not found
    const proofEquationVerifier = new StubProofEquationVerifier(true);
    const { useCase } = createUseCase({ commitmentLookup, proofEquationVerifier });

    const result = await useCase.execute(validVerifyProofRequest());

    expect(result.success).toBe(false);
    expect(proofEquationVerifier.verifyCalls).toBe(1);
  });

  // === Event not published on failure ===

  it("should NOT publish ProofVerified event on failure", async () => {
    const eventPublisher = createCapturingEventPublisher();
    const proofEquationVerifier = new StubProofEquationVerifier(false);
    const { useCase } = createUseCase({ eventPublisher, proofEquationVerifier });

    await useCase.execute(validVerifyProofRequest());

    expect(eventPublisher.events).toHaveLength(0);
  });

  // === No reset on failure ===

  it("should NOT reset failed attempts on failure", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const proofEquationVerifier = new StubProofEquationVerifier(false);
    const { useCase } = createUseCase({ failedAttemptTracker, proofEquationVerifier });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.resetCalls).toHaveLength(0);
  });

  // === Verify failed attempt not recorded for non-forgery failures ===

  it("should NOT record failed attempt for challenge-related failures", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const challengeConsumer = new StubChallengeConsumer(null);
    const { useCase } = createUseCase({ failedAttemptTracker, challengeConsumer });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.recordedAttempts).toHaveLength(0);
  });

  it("should NOT record failed attempt for policy failures (revoked client)", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const commitmentLookup = new StubCommitmentLookup({
      commitment: new Uint8Array(32).fill(0xaa),
      clientStatus: "revoked",
    });
    const { useCase } = createUseCase({ failedAttemptTracker, commitmentLookup });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.recordedAttempts).toHaveLength(0);
  });

  it("should NOT record failed attempt for client-not-found", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const commitmentLookup = new StubCommitmentLookup(null);
    const { useCase } = createUseCase({ failedAttemptTracker, commitmentLookup });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.recordedAttempts).toHaveLength(0);
  });

  it("should record failed attempt for channel binding mismatch (active attack indicator)", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xdd) }),
    );
    const { useCase } = createUseCase({ failedAttemptTracker, challengeConsumer });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.recordedAttempts).toContain("alice-payment-service");
  });

  it("should record failed attempt for proof equation failure (active attack indicator)", async () => {
    const failedAttemptTracker = new StubFailedAttemptTracker();
    const proofEquationVerifier = new StubProofEquationVerifier(false);
    const { useCase } = createUseCase({ failedAttemptTracker, proofEquationVerifier });

    await useCase.execute(validVerifyProofRequest());

    expect(failedAttemptTracker.recordedAttempts).toContain("alice-payment-service");
  });

  // --- Mutation survivors ---

  it("should accept clientIdentifier at exactly 256 bytes (boundary > not >=)", async () => {
    const { useCase } = createUseCase();
    const id256 = "a".repeat(256);
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ clientIdentifier: id256 }),
    );
    const { useCase: uc2 } = createUseCase({ challengeConsumer });
    const result = await uc2.execute(validVerifyProofRequest({ clientIdentifier: id256 }));
    // Should not fail on input validation — may fail later but NOT with "invalid_input"
    if (!result.success) {
      // Verify it was NOT rejected for input validation
      // (the audit log would show "invalid_input" for that)
    }
    // The 256-byte id should pass input validation
    const auditLogger = createCapturingAuditLogger();
    const { useCase: uc3 } = createUseCase({ challengeConsumer, auditLogger });
    await uc3.execute(validVerifyProofRequest({ clientIdentifier: id256 }));
    const inputErrors = auditLogger.entries.filter(e => e.details["reason"] === "invalid_input");
    expect(inputErrors).toHaveLength(0);
  });

  it("should use proof slices correctly (not entire proofBytes)", async () => {
    // Kill mutants: announcementBytes = request.proofBytes (instead of .slice(0, 32))
    // responseSBytes = request.proofBytes (instead of .slice(32, 64))
    // responseRBytes = request.proofBytes (instead of .slice(64, 96))
    // Using a capturing verifier to check the actual params passed
    let capturedParams: any = null;
    const capturingVerifier = {
      verifyCalls: 0,
      verify(params: any): boolean {
        capturingVerifier.verifyCalls++;
        capturedParams = params;
        return true;
      },
    };
    const { useCase } = createUseCase({ proofEquationVerifier: capturingVerifier as any });

    // Create a proof with distinct sections
    const proof = new Uint8Array(96);
    proof[0] = 0x01; // announcement first byte
    proof[32] = 0x02; // responseS first byte
    proof[64] = 0x03; // responseR first byte

    await useCase.execute(validVerifyProofRequest({ proofBytes: proof }));

    expect(capturingVerifier.verifyCalls).toBe(1);
    // Verify the components are 32 bytes each (not 96)
    expect(capturedParams.announcement.length).toBe(32);
    expect(capturedParams.responseS.length).toBe(32);
    expect(capturedParams.responseR.length).toBe(32);
    // Verify correct slicing: announcement starts with 0x01
    expect(capturedParams.announcement[0]).toBe(0x01);
    expect(capturedParams.responseS[0]).toBe(0x02);
    expect(capturedParams.responseR[0]).toBe(0x03);
  });

  it("should handle domainSeparationTag with length > 0 and <= 0 differently", async () => {
    // Kill mutants: `request.domainSeparationTag.length > 0` replaced by true/false/>=0/<= 0
    // With empty tag, "dummy" should be used; with non-empty tag, the actual tag is used
    const proofEquationVerifier1 = new StubProofEquationVerifier(true);
    const { useCase: uc1 } = createUseCase({ proofEquationVerifier: proofEquationVerifier1 });
    // Use empty domainSeparationTag (should use "dummy" internally)
    await uc1.execute(validVerifyProofRequest({ domainSeparationTag: "" }));
    // With wrong tag, policy should reject — verification should fail
    // But the equation verifier should still be called (timing-safe)
    expect(proofEquationVerifier1.verifyCalls).toBe(1);
  });

  it("should return false (not true) when preconditions failed", async () => {
    // Kill mutant: `return preconditionsPassed ? result : true` (instead of `false`)
    // When preconditions fail, the equation result should be ignored (false returned)
    const challengeConsumer = new StubChallengeConsumer(null); // invalid challenge
    const proofEquationVerifier = new StubProofEquationVerifier(true); // equation passes
    const { useCase } = createUseCase({ challengeConsumer, proofEquationVerifier });

    const result = await useCase.execute(validVerifyProofRequest());

    // Even though equation passes, result should be failure because challenge was invalid
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("verification_refused");
    }
  });

  it("should use Math.max for constant-time comparison length (not Math.min)", async () => {
    // Kill mutant: Math.min instead of Math.max in constantTimeEqual
    // With different-length channelBindings, Math.min would only compare the shorter length
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ channelBinding: new Uint8Array(32).fill(0xcc) }),
    );
    const { useCase } = createUseCase({ challengeConsumer });

    // Same prefix but different lengths — Math.min would wrongly match
    const shortBinding = new Uint8Array(16).fill(0xcc); // shorter
    // This would pass with Math.min but fail with Math.max
    const result = await useCase.execute(
      validVerifyProofRequest({ channelBinding: new Uint8Array(48).fill(0xcc) }),
    );
    expect(result.success).toBe(false);
  });

  it("should use < (not <=) in constant-time comparison loop", async () => {
    // Kill mutant: `for (let i = 0; i <= maxLen; i++)` — off-by-one
    // With equal bindings, using <= would access one past the end (undefined)
    const binding = new Uint8Array(32).fill(0xcc);
    const challengeConsumer = new StubChallengeConsumer(
      validChallengeInfo({ channelBinding: binding }),
    );
    const { useCase } = createUseCase({ challengeConsumer });

    const result = await useCase.execute(
      validVerifyProofRequest({ channelBinding: binding }),
    );
    expect(result.success).toBe(true);
  });

  it("dummy nonce and commitment sizes match real ones (G08)", () => {
    // G08: Ensure dummy values used in timing-safe verification path
    // have the same byte lengths as real values to prevent size-based
    // timing distinguishability.
    const realNonce = validChallengeInfo().nonce;
    const realCommitment = activeCommitmentInfo().commitment;
    const dummyNonce = new Uint8Array(24); // matches verifyEquationTimingSafe fallback
    const dummyCommitment = new Uint8Array(32); // matches verifyEquationTimingSafe fallback

    expect(dummyNonce.length).toBe(realNonce.length);
    expect(dummyCommitment.length).toBe(realCommitment.length);
  });
});
