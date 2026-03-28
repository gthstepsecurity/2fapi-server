// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { createVerificationService } from "../../../src/create-verification-service.js";
import type { BatchProofVerifier } from "../../../src/zk-verification/domain/port/outgoing/batch-proof-verifier.js";
import { InputHardeningPolicy } from "../../../src/zk-verification/domain/service/input-hardening-policy.js";
import type { ProofEquationVerifier } from "../../../src/zk-verification/domain/port/outgoing/proof-equation-verifier.js";
import type { TranscriptHasher } from "../../../src/zk-verification/domain/port/outgoing/transcript-hasher.js";
import type { ElementValidator } from "../../../src/zk-verification/domain/port/outgoing/element-validator.js";
import {
  createAllStubs,
  validVerifyProofRequest,
  GENERATOR_G,
  GENERATOR_H,
} from "../../helpers/verification-test-helpers.js";

// Non-stub implementations that pass the factory guards
class TestProofEquationVerifier implements ProofEquationVerifier {
  verify(): boolean { return true; }
}

class TestTranscriptHasher implements TranscriptHasher {
  hash(): Uint8Array { return new Uint8Array(32).fill(0x42); }
}

class TestElementValidator implements ElementValidator {
  isCanonicalScalar(): boolean { return true; }
  isCanonicalPoint(): boolean { return true; }
}

describe("Factory Integration — Sprint 7 Exports", () => {
  it("should expose batchVerifier on the verification service", () => {
    const stubs = createAllStubs();
    const service = createVerificationService({
      challengeConsumer: stubs.challengeConsumer,
      commitmentLookup: stubs.commitmentLookup,
      elementValidator: new TestElementValidator(),
      transcriptHasher: new TestTranscriptHasher(),
      proofEquationVerifier: new TestProofEquationVerifier(),
      failedAttemptTracker: stubs.failedAttemptTracker,
      auditLogger: stubs.auditLogger,
      eventPublisher: stubs.eventPublisher,
      clock: stubs.clock,
      generatorG: GENERATOR_G,
      generatorH: GENERATOR_H,
    });

    expect(service.verifyProof).toBeDefined();
    expect(service.batchVerifier).toBeDefined();
  });

  it("should batch verify proofs via the factory-created service", async () => {
    const stubs = createAllStubs();
    const service = createVerificationService({
      challengeConsumer: stubs.challengeConsumer,
      commitmentLookup: stubs.commitmentLookup,
      elementValidator: new TestElementValidator(),
      transcriptHasher: new TestTranscriptHasher(),
      proofEquationVerifier: new TestProofEquationVerifier(),
      failedAttemptTracker: stubs.failedAttemptTracker,
      auditLogger: stubs.auditLogger,
      eventPublisher: stubs.eventPublisher,
      clock: stubs.clock,
      generatorG: GENERATOR_G,
      generatorH: GENERATOR_H,
    });

    const requests = [
      validVerifyProofRequest(),
      validVerifyProofRequest({ clientIdentifier: "alice-payment-service" }),
    ];
    const results = await service.batchVerifier.verifyBatch(requests);

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it("should expose inputHardeningPolicy on the verification service", () => {
    const stubs = createAllStubs();
    const service = createVerificationService({
      challengeConsumer: stubs.challengeConsumer,
      commitmentLookup: stubs.commitmentLookup,
      elementValidator: new TestElementValidator(),
      transcriptHasher: new TestTranscriptHasher(),
      proofEquationVerifier: new TestProofEquationVerifier(),
      failedAttemptTracker: stubs.failedAttemptTracker,
      auditLogger: stubs.auditLogger,
      eventPublisher: stubs.eventPublisher,
      clock: stubs.clock,
      generatorG: GENERATOR_G,
      generatorH: GENERATOR_H,
    });

    expect(service.inputHardeningPolicy).toBeDefined();
    expect(service.inputHardeningPolicy).toBeInstanceOf(InputHardeningPolicy);
  });
});
