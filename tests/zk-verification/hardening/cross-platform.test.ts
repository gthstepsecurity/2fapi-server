// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VerifyProofUseCase } from "../../../src/zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "../../../src/zk-verification/domain/service/proof-verification-policy.js";
import { Transcript } from "../../../src/zk-verification/domain/model/transcript.js";
import { DomainSeparationTag } from "../../../src/zk-verification/domain/model/domain-separation-tag.js";
import { Proof, PROOF_BYTE_LENGTH } from "../../../src/zk-verification/domain/model/proof.js";
import { GroupElement } from "../../../src/zk-verification/domain/model/group-element.js";
import { ScalarValue } from "../../../src/zk-verification/domain/model/scalar-value.js";
import {
  createAllStubs,
  validVerifyProofRequest,
  validChallengeInfo,
  validProofBytes,
  GENERATOR_G,
  GENERATOR_H,
  StubTranscriptHasher,
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

describe("Cross-Platform / WASM — Deterministic Test Vectors", () => {
  describe("Deterministic test vectors: fixed inputs produce expected output", () => {
    it("should produce deterministic transcript bytes for fixed inputs", () => {
      const tag = DomainSeparationTag.protocol();
      const g = new Uint8Array(32).fill(0x01);
      const h = new Uint8Array(32).fill(0x02);
      const commitment = new Uint8Array(32).fill(0xaa);
      const announcement = new Uint8Array(32).fill(0xbb);
      const nonce = new Uint8Array(24).fill(0xcc);
      const channelBinding = new Uint8Array(32).fill(0xdd);

      const transcript1 = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId: "alice-payment-service",
        nonce, channelBinding,
      });

      const transcript2 = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId: "alice-payment-service",
        nonce, channelBinding,
      });

      const bytes1 = transcript1.toBytes();
      const bytes2 = transcript2.toBytes();

      expect(bytes1.length).toBe(bytes2.length);
      for (let i = 0; i < bytes1.length; i++) {
        expect(bytes1[i]).toBe(bytes2[i]);
      }
    });

    it("should produce consistent proof serialization (round-trip)", () => {
      const announcementBytes = new Uint8Array(32).fill(0x01);
      const responseSBytes = new Uint8Array(32).fill(0x02);
      const responseRBytes = new Uint8Array(32).fill(0x03);

      const announcement = GroupElement.fromBytes(announcementBytes);
      const responseS = ScalarValue.fromBytes(responseSBytes);
      const responseR = ScalarValue.fromBytes(responseRBytes);

      const proof = Proof.create(announcement, responseS, responseR);
      const serialized = proof.toBytes();

      expect(serialized.length).toBe(PROOF_BYTE_LENGTH);

      // Verify each field is correctly placed
      for (let i = 0; i < 32; i++) {
        expect(serialized[i]).toBe(0x01);
      }
      for (let i = 32; i < 64; i++) {
        expect(serialized[i]).toBe(0x02);
      }
      for (let i = 64; i < 96; i++) {
        expect(serialized[i]).toBe(0x03);
      }
    });

    it("should deserialize proof bytes correctly (fromBytes round-trip)", () => {
      const original = new Uint8Array(96);
      original[0] = 0x42; // non-identity announcement
      original[32] = 0x13;
      original[64] = 0x37;

      const proof = Proof.fromBytes(original);
      const roundTripped = proof.toBytes();

      expect(roundTripped.length).toBe(original.length);
      for (let i = 0; i < original.length; i++) {
        expect(roundTripped[i]).toBe(original[i]);
      }
    });

    it("should produce identical domain separation tag bytes across calls", () => {
      const tag1 = DomainSeparationTag.protocol();
      const tag2 = DomainSeparationTag.protocol();

      const bytes1 = tag1.toBytes();
      const bytes2 = tag2.toBytes();

      expect(bytes1.length).toBe(bytes2.length);
      for (let i = 0; i < bytes1.length; i++) {
        expect(bytes1[i]).toBe(bytes2[i]);
      }
    });

    it("should produce known transcript byte length for standard parameters", () => {
      const tag = DomainSeparationTag.protocol(); // "2FApi-v1.0-Sigma" = 16 bytes
      const g = new Uint8Array(32);
      const h = new Uint8Array(32);
      const commitment = new Uint8Array(32);
      const announcement = new Uint8Array(32);
      const nonce = new Uint8Array(24);
      const channelBinding = new Uint8Array(32);
      const clientId = "alice"; // 5 bytes

      const transcript = Transcript.build({
        tag, g, h, commitment, announcement,
        clientId, nonce, channelBinding,
      });

      // Expected: 8 fields * 4 bytes length prefix = 32 bytes overhead
      // Field sizes: 16 + 32 + 32 + 32 + 32 + 5 + 24 + 32 = 205 bytes data
      // Total: 32 + 205 = 237 bytes
      const bytes = transcript.toBytes();
      expect(bytes.length).toBe(237);
    });
  });

  describe("Round-trip: generate proof data then verify (using stubs)", () => {
    it("should succeed for a complete round-trip with matching stubs", async () => {
      const { useCase } = createUseCase();

      const proof = validProofBytes();
      const request = validVerifyProofRequest({ proofBytes: proof });
      const result = await useCase.execute(request);

      expect(result.success).toBe(true);
    });

    it("should verify proof from bytes then serialize back identically", () => {
      const original = validProofBytes();
      const proof = Proof.fromBytes(original);
      const reserialized = proof.toBytes();

      for (let i = 0; i < original.length; i++) {
        expect(reserialized[i]).toBe(original[i]);
      }
    });

    it("should maintain transcript determinism across multiple builds", () => {
      const tag = DomainSeparationTag.protocol();
      const params = {
        tag,
        g: GENERATOR_G,
        h: GENERATOR_H,
        commitment: new Uint8Array(32).fill(0xaa),
        announcement: new Uint8Array(32).fill(0xbb),
        clientId: "test-client",
        nonce: new Uint8Array(24).fill(0xcc),
        channelBinding: new Uint8Array(32).fill(0xdd),
      };

      // Build 10 times and verify all identical
      const transcripts = Array.from({ length: 10 }, () =>
        Transcript.build(params).toBytes(),
      );

      for (let t = 1; t < transcripts.length; t++) {
        expect(transcripts[t]!.length).toBe(transcripts[0]!.length);
        for (let i = 0; i < transcripts[0]!.length; i++) {
          expect(transcripts[t]![i]).toBe(transcripts[0]![i]);
        }
      }
    });
  });
});
