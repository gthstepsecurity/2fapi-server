// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  VerifyProof,
  VerifyProofRequest,
  VerifyProofResponse,
} from "../../domain/port/incoming/verify-proof.js";
import type { RateLimiter } from "../../domain/port/outgoing/rate-limiter.js";
import type { ChallengeConsumer, ChallengeInfo } from "../../domain/port/outgoing/challenge-consumer.js";
import type { CommitmentLookup, CommitmentInfo } from "../../domain/port/outgoing/commitment-lookup.js";
import type { TranscriptHasher } from "../../domain/port/outgoing/transcript-hasher.js";
import type { ProofEquationVerifier } from "../../domain/port/outgoing/proof-equation-verifier.js";
import type { FailedAttemptTracker } from "../../domain/port/outgoing/failed-attempt-tracker.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { VerificationReceiptStore } from "../../domain/port/outgoing/verification-receipt-store.js";
import { ProofVerificationPolicy } from "../../domain/service/proof-verification-policy.js";
import { DomainSeparationTag } from "../../domain/model/domain-separation-tag.js";
import { Transcript } from "../../domain/model/transcript.js";
import { ProofVerified } from "../../domain/event/proof-verified.js";
import { PROOF_BYTE_LENGTH } from "../../domain/model/proof.js";
const MAX_CLIENT_IDENTIFIER_BYTES = 256;

/**
 * Orchestrates the full zero-knowledge proof verification flow.
 *
 * A05 — Future enhancement: Track announcement hashes (A values) to detect
 * nonce (k) reuse across sessions. If two proofs share the same announcement A
 * but different challenge c, the secret can be extracted via PS3-style attack.
 * This would require a new AnnouncementDeduplicationStore driven port.
 *
 * This use case has 12 constructor dependencies, which is acceptable for a
 * top-level orchestration use case that coordinates rate limiting, challenge
 * consumption, commitment lookup, policy validation, transcript construction,
 * proof equation verification, failed attempt tracking, audit logging, event
 * publishing, and clock access. Each dependency is a single-responsibility
 * port — the high count reflects the number of distinct concerns, not a
 * design flaw.
 */
export class VerifyProofUseCase implements VerifyProof {
  constructor(
    private readonly rateLimiter: RateLimiter,
    private readonly challengeConsumer: ChallengeConsumer,
    private readonly commitmentLookup: CommitmentLookup,
    private readonly policy: ProofVerificationPolicy,
    private readonly transcriptHasher: TranscriptHasher,
    private readonly proofEquationVerifier: ProofEquationVerifier,
    private readonly failedAttemptTracker: FailedAttemptTracker,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly clock: Clock,
    private readonly generatorG: Uint8Array,
    private readonly generatorH: Uint8Array,
    private readonly idGenerator?: IdGenerator,
    private readonly receiptStore?: VerificationReceiptStore,
  ) {}

  async execute(request: VerifyProofRequest): Promise<VerifyProofResponse> {
    // 1. Rate limiting check (distinct error — before any expensive operation)
    const allowed = await this.rateLimiter.isAllowed(request.clientIdentifier);
    if (!allowed) {
      return { success: false, error: "rate_limited" };
    }

    // 2. Input validation (clientIdentifier length + proof size)
    const identifierByteLength = new TextEncoder().encode(request.clientIdentifier).length;
    if (identifierByteLength === 0 || identifierByteLength > MAX_CLIENT_IDENTIFIER_BYTES) {
      await this.auditRefused(request.clientIdentifier, "invalid_input");
      return { success: false, error: "verification_refused" };
    }

    if (request.proofBytes.length !== PROOF_BYTE_LENGTH) {
      await this.auditRefused(request.clientIdentifier, "invalid_proof_size");
      return { success: false, error: "verification_refused" };
    }

    // 3. Challenge consumption (atomic check+consume)
    //    Result can be null if consumed/expired/unknown — all indistinguishable
    const challengeInfo = await this.challengeConsumer.consumeIfValid(request.challengeId);

    // 4. Commitment lookup (ALWAYS executed — timing-safe, even if challenge invalid)
    const commitmentInfo = await this.commitmentLookup.findByClientIdentifier(
      request.clientIdentifier,
    );

    // Track whether we should record a failed attempt at the end.
    // Intentional design choice: only set to true for failures that indicate
    // an active attack (channel binding mismatch, proof equation failure).
    // NOT set for missing/expired challenges or policy failures (client not
    // found, revoked, wrong tag) — those are not proof forgery attempts.
    let shouldRecordFailedAttempt = false;
    let verificationPassed = true;

    // 5. Check challenge validity
    if (challengeInfo === null) {
      verificationPassed = false;
    }

    // 5b. Check that the challenge belongs to the requesting client
    if (verificationPassed && challengeInfo !== null) {
      if (challengeInfo.clientIdentifier !== request.clientIdentifier) {
        verificationPassed = false;
      }
    }

    // 6. Check channel binding match (constant-time comparison)
    if (verificationPassed && challengeInfo !== null) {
      if (!this.constantTimeEqual(request.channelBinding, challengeInfo.channelBinding)) {
        verificationPassed = false;
        shouldRecordFailedAttempt = true;
      }
    }

    // 7. Policy validation (tag, encoding, client status)
    const policyError = this.policy.validate({
      commitmentInfo,
      domainSeparationTag: request.domainSeparationTag,
      proofBytes: request.proofBytes,
    });

    if (policyError !== null) {
      verificationPassed = false;
    }

    // 8. Transcript construction + challenge recomputation + equation verification
    //    ALWAYS execute the proof equation verifier for timing safety.
    //    On the failure path, a dummy verification is performed with the same
    //    parameters to ensure all code paths take approximately the same time.
    const equationResult = this.verifyEquationTimingSafe(
      request, challengeInfo, commitmentInfo, verificationPassed,
    );

    if (verificationPassed && !equationResult) {
      verificationPassed = false;
      shouldRecordFailedAttempt = true;
    }

    // === Outcome ===

    if (verificationPassed) {
      // Success path
      await this.failedAttemptTracker.resetFailedAttempts(request.clientIdentifier);

      // Generate and store a one-time verification receipt for token issuance binding
      const receiptId = this.idGenerator?.generate() ?? "";
      if (this.receiptStore && receiptId.length > 0) {
        await this.receiptStore.store(receiptId, request.clientIdentifier);
      }

      await this.auditLogger.log({
        action: "proof_verified",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { challengeId: request.challengeId },
      });

      const nowMs = this.clock.nowMs();
      await this.eventPublisher.publish(
        new ProofVerified(request.clientIdentifier, request.challengeId, nowMs, new Date(nowMs)),
      );

      return { success: true, clientIdentifier: request.clientIdentifier, receiptId };
    }

    // Failure path
    if (shouldRecordFailedAttempt) {
      await this.failedAttemptTracker.recordFailedAttempt(request.clientIdentifier);
    }

    await this.auditLogger.log({
      action: "verification_refused",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      details: { challengeId: request.challengeId },
    });

    return { success: false, error: "verification_refused" };
  }

  /**
   * Executes proof equation verification in a timing-safe manner.
   * When preconditions have already failed, performs a dummy verification
   * with the same computational cost to prevent timing side-channels.
   */
  private verifyEquationTimingSafe(
    request: VerifyProofRequest,
    challengeInfo: ChallengeInfo | null,
    commitmentInfo: CommitmentInfo | null,
    preconditionsPassed: boolean,
  ): boolean {
    // Use real values when available, otherwise use dummy values
    // so the equation verifier is ALWAYS called regardless of path
    const effectiveNonce = challengeInfo?.nonce ?? new Uint8Array(24);
    const effectiveCommitment = commitmentInfo?.commitment ?? new Uint8Array(32);

    // Extract proof components
    const announcementBytes = request.proofBytes.slice(0, 32);
    const responseSBytes = request.proofBytes.slice(32, 64);
    const responseRBytes = request.proofBytes.slice(64, 96);

    // Build transcript
    const tag = DomainSeparationTag.fromString(
      request.domainSeparationTag.length > 0
        ? request.domainSeparationTag
        : "2FApi-v1.0-Sigma",
    );
    const transcript = Transcript.build({
      tag,
      g: this.generatorG,
      h: this.generatorH,
      commitment: effectiveCommitment,
      announcement: announcementBytes,
      clientId: request.clientIdentifier,
      nonce: effectiveNonce,
      channelBinding: request.channelBinding,
    });

    // Recompute challenge scalar from transcript (server NEVER accepts c from client)
    const challengeScalar = this.transcriptHasher.hash(transcript.toBytes());

    // Zero-challenge guard: if c=0, the equation z_s·G + z_r·H == A + 0·C
    // becomes trivially satisfiable without knowing any secret. This can happen
    // if the native transcript hasher crashes and returns zeros.
    if (this.isAllZeros(challengeScalar)) {
      return false;
    }

    // Verify proof equation: z_s·G + z_r·H == A + c·C
    const result = this.proofEquationVerifier.verify({
      generatorG: this.generatorG,
      generatorH: this.generatorH,
      commitment: effectiveCommitment,
      announcement: announcementBytes,
      challenge: challengeScalar,
      responseS: responseSBytes,
      responseR: responseRBytes,
    });

    // Only trust the result if all preconditions passed
    return preconditionsPassed ? result : false;
  }

  /**
   * Constant-time comparison using XOR accumulator.
   * When lengths differ, iterates over the longer array to avoid
   * timing leakage that would reveal the length mismatch early.
   */
  private constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    const maxLen = Math.max(a.length, b.length);
    let acc = a.length ^ b.length; // non-zero if lengths differ
    for (let i = 0; i < maxLen; i++) {
      acc |= (a[i] ?? 0) ^ (b[i] ?? 0);
    }
    return acc === 0;
  }

  /**
   * Checks if a byte array is all zeros (constant-time via accumulator).
   * Used to detect zero-challenge scalars that would trivialize the proof equation.
   */
  private isAllZeros(bytes: Uint8Array): boolean {
    let acc = 0;
    for (let i = 0; i < bytes.length; i++) {
      acc |= bytes[i]!;
    }
    return acc === 0;
  }

  private async auditRefused(clientIdentifier: string, reason: string): Promise<void> {
    await this.auditLogger.log({
      action: "verification_refused",
      clientIdentifier,
      timestamp: new Date(),
      details: { reason },
    });
  }
}
