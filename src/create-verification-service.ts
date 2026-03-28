// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VerifyProof } from "./zk-verification/domain/port/incoming/verify-proof.js";
import type { RateLimiter } from "./zk-verification/domain/port/outgoing/rate-limiter.js";
import type { ChallengeConsumer } from "./zk-verification/domain/port/outgoing/challenge-consumer.js";
import type { CommitmentLookup } from "./zk-verification/domain/port/outgoing/commitment-lookup.js";
import type { ElementValidator } from "./zk-verification/domain/port/outgoing/element-validator.js";
import type { TranscriptHasher } from "./zk-verification/domain/port/outgoing/transcript-hasher.js";
import type { ProofEquationVerifier } from "./zk-verification/domain/port/outgoing/proof-equation-verifier.js";
import type { FailedAttemptTracker } from "./zk-verification/domain/port/outgoing/failed-attempt-tracker.js";
import type { AuditLogger } from "./zk-verification/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./zk-verification/domain/port/outgoing/event-publisher.js";
import type { Clock } from "./zk-verification/domain/port/outgoing/clock.js";
import type { BatchProofVerifier } from "./zk-verification/domain/port/outgoing/batch-proof-verifier.js";
import { VerifyProofUseCase } from "./zk-verification/application/usecase/verify-proof.usecase.js";
import { ProofVerificationPolicy } from "./zk-verification/domain/service/proof-verification-policy.js";
import { BatchVerificationService } from "./zk-verification/domain/service/batch-verification-service.js";
import { InputHardeningPolicy } from "./zk-verification/domain/service/input-hardening-policy.js";
import { StubProofEquationVerifier } from "./zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
import { StubTranscriptHasher } from "./zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
import { StubElementValidator } from "./zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";

export interface VerificationServiceDependencies {
  readonly challengeConsumer: ChallengeConsumer;
  readonly commitmentLookup: CommitmentLookup;
  readonly elementValidator: ElementValidator;
  readonly transcriptHasher: TranscriptHasher;
  readonly proofEquationVerifier: ProofEquationVerifier;
  readonly failedAttemptTracker: FailedAttemptTracker;
  readonly auditLogger: AuditLogger;
  readonly eventPublisher: EventPublisher;
  readonly clock: Clock;
  readonly generatorG: Uint8Array;
  readonly generatorH: Uint8Array;
  readonly rateLimiter?: RateLimiter;
  readonly environment?: "development" | "test" | "production";
}

export interface VerificationService {
  readonly verifyProof: VerifyProof;
  readonly batchVerifier: BatchProofVerifier;
  readonly inputHardeningPolicy: InputHardeningPolicy;
}

export function createVerificationService(deps: VerificationServiceDependencies): VerificationService {
  if (deps.environment === "production") {
    if (deps.proofEquationVerifier instanceof StubProofEquationVerifier) {
      throw new Error(
        "ProofEquationVerifier is required — never deploy with StubProofEquationVerifier",
      );
    }
    if (deps.transcriptHasher instanceof StubTranscriptHasher) {
      throw new Error(
        "TranscriptHasher is required — never deploy with StubTranscriptHasher",
      );
    }
    if (deps.elementValidator instanceof StubElementValidator) {
      throw new Error(
        "ElementValidator is required — never deploy with StubElementValidator",
      );
    }
  }

  const policy = new ProofVerificationPolicy(deps.elementValidator);

  const noopRateLimiter: RateLimiter = {
    async isAllowed(): Promise<boolean> {
      return true;
    },
  };

  const verifyProof = new VerifyProofUseCase(
    deps.rateLimiter ?? noopRateLimiter,
    deps.challengeConsumer,
    deps.commitmentLookup,
    policy,
    deps.transcriptHasher,
    deps.proofEquationVerifier,
    deps.failedAttemptTracker,
    deps.auditLogger,
    deps.eventPublisher,
    deps.clock,
    deps.generatorG,
    deps.generatorH,
  );

  const batchVerifier = new BatchVerificationService(verifyProof);
  const inputHardeningPolicy = new InputHardeningPolicy();

  return { verifyProof, batchVerifier, inputHardeningPolicy };
}
