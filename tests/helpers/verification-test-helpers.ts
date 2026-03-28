// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RateLimiter } from "../../src/zk-verification/domain/port/outgoing/rate-limiter.js";
import type { AuditLogger, AuditEntry } from "../../src/zk-verification/domain/port/outgoing/audit-logger.js";
import type { EventPublisher, DomainEvent } from "../../src/zk-verification/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../src/zk-verification/domain/port/outgoing/clock.js";
import type { VerifyProofRequest } from "../../src/zk-verification/domain/port/incoming/verify-proof.js";
import { StubElementValidator } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
import { StubCommitmentLookup } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-commitment-lookup.js";
import { StubChallengeConsumer } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-challenge-consumer.js";
import { StubProofEquationVerifier } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
import { StubTranscriptHasher } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
import { StubFailedAttemptTracker } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-failed-attempt-tracker.js";
import type { CommitmentInfo } from "../../src/zk-verification/domain/port/outgoing/commitment-lookup.js";
import type { ChallengeInfo } from "../../src/zk-verification/domain/port/outgoing/challenge-consumer.js";

export { StubElementValidator } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
export { StubCommitmentLookup } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-commitment-lookup.js";
export { StubChallengeConsumer } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-challenge-consumer.js";
export { StubProofEquationVerifier } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
export { StubTranscriptHasher } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
export { StubFailedAttemptTracker } from "../../src/zk-verification/infrastructure/adapter/outgoing/stub-failed-attempt-tracker.js";

// --- Fixed public parameters for stubs ---
export const GENERATOR_G = new Uint8Array(32).fill(0x01);
export const GENERATOR_H = new Uint8Array(32).fill(0x02);

// --- Factory functions ---

export function createStubRateLimiter(allowed = true): RateLimiter {
  return {
    async isAllowed(): Promise<boolean> {
      return allowed;
    },
  };
}

export function createCapturingAuditLogger(): AuditLogger & { entries: AuditEntry[] } {
  const logger = {
    entries: [] as AuditEntry[],
    async log(entry: AuditEntry): Promise<void> {
      logger.entries.push(entry);
    },
  };
  return logger;
}

export function createCapturingEventPublisher(): EventPublisher & { events: DomainEvent[] } {
  const publisher = {
    events: [] as DomainEvent[],
    async publish(event: DomainEvent): Promise<void> {
      publisher.events.push(event);
    },
  };
  return publisher;
}

export function createStubClock(nowMs = 1000000): Clock {
  return { nowMs: () => nowMs };
}

export function activeCommitmentInfo(): CommitmentInfo {
  return {
    commitment: new Uint8Array(32).fill(0xaa),
    clientStatus: "active",
  };
}

export function validChallengeInfo(
  overrides: Partial<ChallengeInfo> = {},
): ChallengeInfo {
  return {
    clientIdentifier: overrides.clientIdentifier ?? "alice-payment-service",
    nonce: overrides.nonce ?? new Uint8Array(24).fill(0xbb),
    channelBinding: overrides.channelBinding ?? new Uint8Array(32).fill(0xcc),
  };
}

/**
 * Creates a valid 96-byte proof: 32 (announcement) + 32 (responseS) + 32 (responseR).
 * Announcement is non-identity (first byte non-zero).
 */
export function validProofBytes(): Uint8Array {
  const bytes = new Uint8Array(96);
  bytes[0] = 0x01; // non-identity announcement
  bytes[32] = 0x02; // responseS
  bytes[64] = 0x03; // responseR
  return bytes;
}

export function validVerifyProofRequest(
  overrides: Partial<VerifyProofRequest> = {},
): VerifyProofRequest {
  return {
    clientIdentifier: overrides.clientIdentifier ?? "alice-payment-service",
    challengeId: overrides.challengeId ?? "challenge-001",
    proofBytes: overrides.proofBytes ?? validProofBytes(),
    channelBinding: overrides.channelBinding ?? new Uint8Array(32).fill(0xcc),
    domainSeparationTag: overrides.domainSeparationTag ?? "2FApi-v1.0-Sigma",
  };
}

export interface AllStubs {
  rateLimiter: RateLimiter;
  challengeConsumer: StubChallengeConsumer;
  commitmentLookup: StubCommitmentLookup;
  elementValidator: StubElementValidator;
  transcriptHasher: StubTranscriptHasher;
  proofEquationVerifier: StubProofEquationVerifier;
  failedAttemptTracker: StubFailedAttemptTracker;
  auditLogger: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher: ReturnType<typeof createCapturingEventPublisher>;
  clock: Clock;
}

/**
 * Creates a full set of stubs configured for a happy-path scenario.
 */
export function createAllStubs(overrides: Partial<AllStubs> = {}): AllStubs {
  return {
    rateLimiter: overrides.rateLimiter ?? createStubRateLimiter(true),
    challengeConsumer: overrides.challengeConsumer ?? new StubChallengeConsumer(validChallengeInfo()),
    commitmentLookup: overrides.commitmentLookup ?? new StubCommitmentLookup(activeCommitmentInfo()),
    elementValidator: overrides.elementValidator ?? new StubElementValidator(),
    transcriptHasher: overrides.transcriptHasher ?? new StubTranscriptHasher(),
    proofEquationVerifier: overrides.proofEquationVerifier ?? new StubProofEquationVerifier(true),
    failedAttemptTracker: overrides.failedAttemptTracker ?? new StubFailedAttemptTracker(),
    auditLogger: overrides.auditLogger ?? createCapturingAuditLogger(),
    eventPublisher: overrides.eventPublisher ?? createCapturingEventPublisher(),
    clock: overrides.clock ?? createStubClock(),
  };
}
