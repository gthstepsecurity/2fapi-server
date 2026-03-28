// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  createVerificationService,
  type VerificationServiceDependencies,
} from "../../src/create-verification-service.js";
import { StubProofEquationVerifier } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
import { StubTranscriptHasher } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
import { StubElementValidator } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
import { StubChallengeConsumer } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-challenge-consumer.js";
import { StubCommitmentLookup } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-commitment-lookup.js";
import { StubFailedAttemptTracker } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-failed-attempt-tracker.js";
import type { ProofEquationVerifier } from "../../src/zk-verification/domain/port/outgoing/proof-equation-verifier.js";
import type { TranscriptHasher } from "../../src/zk-verification/domain/port/outgoing/transcript-hasher.js";
import type { ElementValidator } from "../../src/zk-verification/domain/port/outgoing/element-validator.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
  GENERATOR_G,
  GENERATOR_H,
} from "../helpers/verification-test-helpers.js";

function baseDeps(overrides: {
  proofEquationVerifier?: ProofEquationVerifier;
  transcriptHasher?: TranscriptHasher;
  elementValidator?: ElementValidator;
  environment?: "development" | "test" | "production";
} = {}): VerificationServiceDependencies {
  return {
    challengeConsumer: new StubChallengeConsumer(),
    commitmentLookup: new StubCommitmentLookup(),
    elementValidator: overrides.elementValidator ?? new StubElementValidator(),
    transcriptHasher: overrides.transcriptHasher ?? new StubTranscriptHasher(),
    proofEquationVerifier: overrides.proofEquationVerifier ?? new StubProofEquationVerifier(true),
    failedAttemptTracker: new StubFailedAttemptTracker(),
    auditLogger: createCapturingAuditLogger(),
    eventPublisher: createCapturingEventPublisher(),
    clock: createStubClock(),
    generatorG: GENERATOR_G,
    generatorH: GENERATOR_H,
    environment: overrides.environment,
  };
}

// Real implementations for testing the guard pass-through
class RealProofEquationVerifier implements ProofEquationVerifier {
  verify(): boolean { return false; }
}

class RealTranscriptHasher implements TranscriptHasher {
  hash(): Uint8Array { return new Uint8Array(32); }
}

class RealElementValidator implements ElementValidator {
  isCanonicalScalar(): boolean { return true; }
  isCanonicalPoint(): boolean { return true; }
}

describe("ITEM 2 — Stub Crypto Adapter Guards in createVerificationService", () => {
  it("throws when proofEquationVerifier is a StubProofEquationVerifier in production", () => {
    const deps = baseDeps({
      proofEquationVerifier: new StubProofEquationVerifier(true),
      transcriptHasher: new RealTranscriptHasher(),
      elementValidator: new RealElementValidator(),
      environment: "production",
    });
    expect(() => createVerificationService(deps)).toThrow(
      "StubProofEquationVerifier",
    );
  });

  it("throws when transcriptHasher is a StubTranscriptHasher in production", () => {
    const deps = baseDeps({
      proofEquationVerifier: new RealProofEquationVerifier(),
      transcriptHasher: new StubTranscriptHasher(),
      elementValidator: new RealElementValidator(),
      environment: "production",
    });
    expect(() => createVerificationService(deps)).toThrow(
      "StubTranscriptHasher",
    );
  });

  it("throws when elementValidator is a StubElementValidator in production", () => {
    const deps = baseDeps({
      proofEquationVerifier: new RealProofEquationVerifier(),
      transcriptHasher: new RealTranscriptHasher(),
      elementValidator: new StubElementValidator(),
      environment: "production",
    });
    expect(() => createVerificationService(deps)).toThrow(
      "StubElementValidator",
    );
  });

  it("allows stubs in development", () => {
    const deps = baseDeps({ environment: "development" });
    const service = createVerificationService(deps);
    expect(service.verifyProof).toBeDefined();
  });

  it("allows stubs when environment is omitted", () => {
    const deps = baseDeps();
    const service = createVerificationService(deps);
    expect(service.verifyProof).toBeDefined();
  });

  it("succeeds when all real implementations are provided in production", () => {
    const deps = baseDeps({
      proofEquationVerifier: new RealProofEquationVerifier(),
      transcriptHasher: new RealTranscriptHasher(),
      elementValidator: new RealElementValidator(),
      environment: "production",
    });
    const service = createVerificationService(deps);
    expect(service.verifyProof).toBeDefined();
    expect(service.batchVerifier).toBeDefined();
    expect(service.inputHardeningPolicy).toBeDefined();
  });
});
