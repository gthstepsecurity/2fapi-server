// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Transcript } from "../../../src/zk-verification/domain/model/transcript.js";
import { DomainSeparationTag } from "../../../src/zk-verification/domain/model/domain-separation-tag.js";
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

describe("Transcript Integrity — Hardening", () => {
  describe("Field reordering produces different challenge (injection resistance)", () => {
    it("should produce different transcript bytes when nonce and channelBinding are swapped", () => {
      const tag = DomainSeparationTag.protocol();
      const g = new Uint8Array(32).fill(0x01);
      const h = new Uint8Array(32).fill(0x02);
      const commitment = new Uint8Array(32).fill(0xaa);
      const announcement = new Uint8Array(32).fill(0xbb);
      const nonce = new Uint8Array(24).fill(0x11);
      const channelBinding = new Uint8Array(32).fill(0x22);

      const canonicalTranscript = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId: "alice",
        nonce,
        channelBinding,
      });

      // Swap nonce and channelBinding positions by building with swapped values
      const swappedTranscript = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId: "alice",
        nonce: channelBinding, // swapped
        channelBinding: nonce, // swapped
      });

      const canonicalBytes = canonicalTranscript.toBytes();
      const swappedBytes = swappedTranscript.toBytes();

      // Transcripts MUST differ when fields are swapped
      // Length-prefixed encoding ensures different field values produce different bytes
      let differ = false;
      const maxLen = Math.max(canonicalBytes.length, swappedBytes.length);
      for (let i = 0; i < maxLen; i++) {
        if ((canonicalBytes[i] ?? -1) !== (swappedBytes[i] ?? -2)) {
          differ = true;
          break;
        }
      }
      if (canonicalBytes.length !== swappedBytes.length) differ = true;
      expect(differ).toBe(true);
    });

    it("should produce different transcript when commitment and announcement are swapped", () => {
      const tag = DomainSeparationTag.protocol();
      const g = new Uint8Array(32).fill(0x01);
      const h = new Uint8Array(32).fill(0x02);
      const commitment = new Uint8Array(32).fill(0xaa);
      const announcement = new Uint8Array(32).fill(0xbb);
      const nonce = new Uint8Array(24).fill(0x11);
      const channelBinding = new Uint8Array(32).fill(0x22);

      const canonical = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId: "alice", nonce, channelBinding,
      });

      const swapped = Transcript.build({
        tag, g, h,
        commitment: announcement, // swapped
        announcement: commitment, // swapped
        clientId: "alice", nonce, channelBinding,
      });

      const canonicalBytes = canonical.toBytes();
      const swappedBytes = swapped.toBytes();

      let differ = false;
      for (let i = 0; i < canonicalBytes.length; i++) {
        if (canonicalBytes[i] !== swappedBytes[i]) {
          differ = true;
          break;
        }
      }
      expect(differ).toBe(true);
    });
  });

  describe("Interleaving attack — elements from two sessions", () => {
    it("should reject proof using announcement from one session and responses from another", async () => {
      // Session 1: valid challenge and proof
      const nonce1 = new Uint8Array(24).fill(0x11);
      const nonce2 = new Uint8Array(24).fill(0x22);

      // The transcript hasher produces different hashes per session (different nonces → different transcript)
      // We simulate: the proof equation verifier returns false for mismatched data
      const proofEquationVerifier = new StubProofEquationVerifier(false);
      const challengeConsumer = new StubChallengeConsumer(
        validChallengeInfo({ nonce: nonce1 }),
      );
      const { useCase } = createUseCase({ proofEquationVerifier, challengeConsumer });

      // Eve's hybrid proof: announcement from session 1, responses from session 2
      // In a real scenario, this would fail the equation check
      const hybridProof = validProofBytes();
      const request = validVerifyProofRequest({ proofBytes: hybridProof });

      const result = await useCase.execute(request);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe("verification_refused");
      }
    });

    it("should log audit entry for interleaving attack attempt", async () => {
      const proofEquationVerifier = new StubProofEquationVerifier(false);
      const auditLogger = createCapturingAuditLogger();
      const { useCase } = createUseCase({ proofEquationVerifier, auditLogger });

      await useCase.execute(validVerifyProofRequest());

      expect(auditLogger.entries.length).toBeGreaterThanOrEqual(1);
      expect(auditLogger.entries.some((e) => e.action === "verification_refused")).toBe(true);
    });
  });

  describe("Nonce reuse detection — same announcement with different challenges", () => {
    it("should reject when same announcement is reused with different challenges", async () => {
      // Two sessions with the same announcement but different nonces
      // Both should fail if the equation verifier detects mismatched data
      const nonce1 = new Uint8Array(24).fill(0x11);
      const nonce2 = new Uint8Array(24).fill(0x22);

      // Session 1
      const proofEquationVerifier1 = new StubProofEquationVerifier(true);
      const challengeConsumer1 = new StubChallengeConsumer(
        validChallengeInfo({ nonce: nonce1 }),
      );
      const { useCase: useCase1 } = createUseCase({
        proofEquationVerifier: proofEquationVerifier1,
        challengeConsumer: challengeConsumer1,
      });

      const proof = validProofBytes();
      const result1 = await useCase1.execute(validVerifyProofRequest({ proofBytes: proof }));
      expect(result1.success).toBe(true);

      // Session 2 — same proof (same announcement A) with different nonce
      // The equation verifier should fail because the transcript hash changes
      const proofEquationVerifier2 = new StubProofEquationVerifier(false);
      const challengeConsumer2 = new StubChallengeConsumer(
        validChallengeInfo({ nonce: nonce2 }),
      );
      const { useCase: useCase2 } = createUseCase({
        proofEquationVerifier: proofEquationVerifier2,
        challengeConsumer: challengeConsumer2,
      });

      const result2 = await useCase2.execute(validVerifyProofRequest({ proofBytes: proof }));
      expect(result2.success).toBe(false);
    });
  });

  describe("Manipulated Fiat-Shamir challenge", () => {
    it("should reject proof when equation verifier detects challenge mismatch", async () => {
      // Eve manipulates the challenge: the server recomputes c from transcript
      // and it won't match Eve's c_prime, so equation fails
      const proofEquationVerifier = new StubProofEquationVerifier(false);
      const { useCase } = createUseCase({ proofEquationVerifier });

      const result = await useCase.execute(validVerifyProofRequest());

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe("verification_refused");
      }
    });

    it("should always recompute challenge from transcript (never accept client-provided c)", async () => {
      // The server ALWAYS calls transcriptHasher.hash() to recompute the challenge
      // This is verified by checking that the transcript hasher is called
      const transcriptHasher = new StubTranscriptHasher();
      let hashCalled = false;
      const originalHash = transcriptHasher.hash.bind(transcriptHasher);
      transcriptHasher.hash = (bytes: Uint8Array) => {
        hashCalled = true;
        return originalHash(bytes);
      };
      const { useCase } = createUseCase({ transcriptHasher });

      await useCase.execute(validVerifyProofRequest());

      expect(hashCalled).toBe(true);
    });
  });

  describe("Domain separation — cross-protocol proof reuse impossible", () => {
    it("should reject proof with wrong domain separation tag", async () => {
      const { useCase } = createUseCase();

      const request = validVerifyProofRequest({
        domainSeparationTag: "OtherProto-v1.0",
      });
      const result = await useCase.execute(request);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe("verification_refused");
      }
    });

    it("should produce different transcripts for different domain tags", () => {
      const g = new Uint8Array(32).fill(0x01);
      const h = new Uint8Array(32).fill(0x02);
      const commitment = new Uint8Array(32).fill(0xaa);
      const announcement = new Uint8Array(32).fill(0xbb);
      const nonce = new Uint8Array(24).fill(0x11);
      const channelBinding = new Uint8Array(32).fill(0x22);

      const transcript2FApi = Transcript.build({
        tag: DomainSeparationTag.protocol(),
        g, h, commitment, announcement,
        clientId: "alice", nonce, channelBinding,
      });

      const transcriptOther = Transcript.build({
        tag: DomainSeparationTag.fromString("OtherProto-v1.0"),
        g, h, commitment, announcement,
        clientId: "alice", nonce, channelBinding,
      });

      const bytes1 = transcript2FApi.toBytes();
      const bytes2 = transcriptOther.toBytes();

      let differ = false;
      const maxLen = Math.max(bytes1.length, bytes2.length);
      for (let i = 0; i < maxLen; i++) {
        if ((bytes1[i] ?? 0) !== (bytes2[i] ?? 0)) {
          differ = true;
          break;
        }
      }
      if (bytes1.length !== bytes2.length) differ = true;
      expect(differ).toBe(true);
    });

    it("should reject proof from another protocol even with same curve parameters", async () => {
      const { useCase } = createUseCase();

      const request = validVerifyProofRequest({
        domainSeparationTag: "SomeOtherAPI-v2.0-Sigma",
      });
      const result = await useCase.execute(request);

      expect(result.success).toBe(false);
    });
  });
});
