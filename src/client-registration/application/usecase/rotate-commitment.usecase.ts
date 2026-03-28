// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RotateCommitment, RotateCommitmentRequest, RotateCommitmentResponse } from "../../domain/port/incoming/rotate-commitment.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { TokenInvalidator } from "../../domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { RateLimiter } from "../../domain/port/outgoing/rate-limiter.js";
import type { RotationPolicy } from "../../domain/service/rotation-policy.js";
import type { RecoveryHashStore } from "../../domain/port/outgoing/recovery-hash-store.js";
import type { Argon2Hasher } from "../../domain/port/outgoing/argon2-hasher.js";
import type { RecoveryPhraseGenerator } from "../../domain/service/recovery-phrase-generator.js";
import type { RecoveryConfig } from "../../domain/model/recovery-config.js";
import { Commitment } from "../../domain/model/commitment.js";
import { CommitmentRotated } from "../../domain/event/commitment-rotated.js";
import { RecoveryVerifier } from "../../domain/service/recovery-verifier.js";

export interface RotateCommitmentRecoveryOptions {
  readonly recoveryHashStore: RecoveryHashStore;
  readonly phraseGenerator: RecoveryPhraseGenerator;
  readonly argon2Hasher: Argon2Hasher;
  readonly recoveryConfig: RecoveryConfig;
}

export class RotateCommitmentUseCase implements RotateCommitment {
  private readonly recoveryOptions: RotateCommitmentRecoveryOptions | undefined;

  constructor(
    private readonly policy: RotationPolicy,
    private readonly repository: ClientRepository,
    private readonly tokenInvalidator: TokenInvalidator,
    private readonly challengeInvalidator: ChallengeInvalidator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly rateLimiter: RateLimiter,
    recoveryOptions?: RotateCommitmentRecoveryOptions,
  ) {
    this.recoveryOptions = recoveryOptions;
  }

  async execute(request: RotateCommitmentRequest): Promise<RotateCommitmentResponse> {
    const allowed = await this.rateLimiter.isAllowed(request.clientIdentifier);
    if (!allowed) {
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: "RATE_LIMITED" },
      });
      return { success: false, error: "rotation_failed" };
    }

    const client = await this.repository.findByIdentifier(request.clientIdentifier);

    if (!client) {
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_FOUND" },
      });
      return { success: false, error: "rotation_failed" };
    }

    if (client.status !== "active") {
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_ACTIVE" },
      });
      return { success: false, error: "rotation_failed" };
    }

    const validationError = this.policy.validate(
      client.commitment,
      request.currentProofBytes,
      request.newCommitmentBytes,
      request.newCommitmentProofBytes,
    );

    if (validationError) {
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: validationError.code },
      });
      return { success: false, error: "rotation_failed" };
    }

    const newCommitment = Commitment.fromBytes(request.newCommitmentBytes);
    const rotatedClient = client.rotateCommitment(newCommitment);

    // BB02: Re-read client to detect concurrent revocation between initial read and update.
    // If status changed (e.g., revoked by another process), abort the rotation.
    const freshClient = await this.repository.findByIdentifier(request.clientIdentifier);
    if (!freshClient || freshClient.status !== "active") {
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: "CONCURRENT_STATUS_CHANGE" },
      });
      return { success: false, error: "rotation_failed" };
    }

    /**
     * Transaction ordering for rotation rollback safety:
     * 1. repository.update(rotatedClient) — persist the new commitment
     * 2. eventPublisher.publish — emit integration event
     * 3. tokenInvalidator.invalidateAllForClient — revoke all tokens
     * 4. challengeInvalidator.invalidateAllForClient — revoke all challenges
     *
     * Rationale: if event publish fails (step 2), rollback is clean because
     * tokens were NOT yet invalidated. If token/challenge invalidation fails
     * (step 3/4), the commitment is already stored and the event published,
     * so we log a warning but don't rollback — the tokens will be caught
     * by real-time status checks at verification time.
     */
    await this.repository.update(rotatedClient);

    try {
      await this.eventPublisher.publish(
        new CommitmentRotated(request.clientIdentifier, rotatedClient.commitmentVersion),
      );
    } catch {
      // Event publisher failure → rollback commitment only
      // Tokens were NOT invalidated yet, so state is consistent
      try {
        await this.repository.update(client);
      } catch {
        // Best effort rollback
      }
      await this.auditLogger.log({
        eventType: "rotation_failed",
        timestamp: new Date(),
        metadata: { reason: "EVENT_PUBLISH_FAILED" },
      });
      return { success: false, error: "rotation_failed" };
    }

    // Token and challenge invalidation — best effort after event published
    try {
      await this.tokenInvalidator.invalidateAllForClient(request.clientIdentifier);
    } catch {
      await this.auditLogger.log({
        eventType: "rotation_warning",
        timestamp: new Date(),
        metadata: { reason: "TOKEN_INVALIDATION_FAILED" },
      });
    }

    try {
      await this.challengeInvalidator.invalidateAllForClient(request.clientIdentifier);
    } catch {
      await this.auditLogger.log({
        eventType: "rotation_warning",
        timestamp: new Date(),
        metadata: { reason: "CHALLENGE_INVALIDATION_FAILED" },
      });
    }

    // BF02: Generate new recovery phrase and store new hash after rotation
    if (this.recoveryOptions) {
      const { recoveryHashStore, phraseGenerator, argon2Hasher, recoveryConfig } = this.recoveryOptions;
      const recoveryVerifier = new RecoveryVerifier(argon2Hasher);
      const newPhrase = phraseGenerator.generate(recoveryConfig.wordCount);
      const newWords = newPhrase.toDisplayString().split(" ");
      const newHash = await recoveryVerifier.deriveHash(
        newWords,
        request.clientIdentifier,
        recoveryConfig,
      );
      await recoveryHashStore.storeHash(request.clientIdentifier, newHash);
    }

    await this.auditLogger.log({
      eventType: "commitment_rotated",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
    });

    return { success: true };
  }
}
