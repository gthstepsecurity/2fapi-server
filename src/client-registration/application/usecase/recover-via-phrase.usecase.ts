// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  RecoverViaPhrase,
  RecoverViaPhraseRequest,
  RecoverViaPhraseResponse,
} from "../../domain/port/incoming/recover-via-phrase.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { RecoveryHashStore } from "../../domain/port/outgoing/recovery-hash-store.js";
import type { Argon2Hasher } from "../../domain/port/outgoing/argon2-hasher.js";
import type { TokenInvalidator } from "../../domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { RecoveryConfig } from "../../domain/model/recovery-config.js";
import { Commitment } from "../../domain/model/commitment.js";
import { RecoveryVerifier } from "../../domain/service/recovery-verifier.js";
import { ClientRecovered } from "../../domain/event/client-recovered.js";
import type { ConcurrencyLimiter } from "../../../shared/concurrency-limiter.js";
import type { RecoveryPhraseGenerator } from "../../domain/service/recovery-phrase-generator.js";

export interface RecoverViaPhraseUseCaseOptions {
  readonly concurrencyLimiter?: ConcurrencyLimiter;
  readonly phraseGenerator?: RecoveryPhraseGenerator;
}

export class RecoverViaPhraseUseCase implements RecoverViaPhrase {
  private readonly recoveryVerifier: RecoveryVerifier;
  private readonly concurrencyLimiter: ConcurrencyLimiter | undefined;
  private readonly phraseGenerator: RecoveryPhraseGenerator | undefined;

  constructor(
    private readonly repository: ClientRepository,
    private readonly recoveryHashStore: RecoveryHashStore,
    argon2Hasher: Argon2Hasher,
    private readonly tokenInvalidator: TokenInvalidator,
    private readonly challengeInvalidator: ChallengeInvalidator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly config: RecoveryConfig,
    options?: RecoverViaPhraseUseCaseOptions,
  ) {
    this.recoveryVerifier = new RecoveryVerifier(argon2Hasher);
    this.concurrencyLimiter = options?.concurrencyLimiter;
    this.phraseGenerator = options?.phraseGenerator;
  }

  async execute(request: RecoverViaPhraseRequest): Promise<RecoverViaPhraseResponse> {
    // Check recovery mode allows phrase recovery
    if (this.config.recoveryMode === "external_only") {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        timestamp: new Date(),
        metadata: { reason: "PHRASE_RECOVERY_DISABLED" },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Early lockout check — refuse BEFORE doing expensive Argon2 hash
    const attemptCount = await this.recoveryHashStore.getAttemptCount(request.clientIdentifier);
    if (attemptCount >= this.config.maxRecoveryAttempts) {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "ALREADY_LOCKED", attempts: attemptCount },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Find client
    const client = await this.repository.findByIdentifier(request.clientIdentifier);

    if (!client) {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_FOUND" },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Check client is suspended
    if (client.status !== "suspended") {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_SUSPENDED" },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Get stored hash
    const storedHash = await this.recoveryHashStore.getHash(request.clientIdentifier);
    if (!storedHash) {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        timestamp: new Date(),
        metadata: { reason: "NO_RECOVERY_HASH" },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Acquire concurrency slot before expensive Argon2 operation
    if (this.concurrencyLimiter && !this.concurrencyLimiter.acquire()) {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "CONCURRENCY_LIMIT_REACHED" },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Verify words against stored hash
    let isValid: boolean;
    try {
      isValid = await this.recoveryVerifier.verify(
        request.words,
        request.clientIdentifier,
        storedHash,
        this.config,
      );
    } finally {
      this.concurrencyLimiter?.release();
    }

    if (!isValid) {
      // Record failed attempt
      const attemptCount = await this.recoveryHashStore.recordFailedAttempt(
        request.clientIdentifier,
      );

      if (attemptCount >= this.config.maxRecoveryAttempts) {
        await this.auditLogger.log({
          eventType: "recovery_locked",
          clientIdentifier: request.clientIdentifier,
          timestamp: new Date(),
          metadata: { attempts: attemptCount },
        });
      }

      await this.auditLogger.log({
        eventType: "recovery_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "HASH_MISMATCH", attempts: attemptCount },
      });
      return { success: false, error: "recovery_failed" };
    }

    // Reactivate with new commitment
    const newCommitment = Commitment.fromBytes(request.newCommitmentBytes);
    const reactivatedClient = client.reactivate(newCommitment);

    // BB08: Re-read client to detect concurrent recovery (optimistic locking via commitmentVersion)
    const freshClient = await this.repository.findByIdentifier(request.clientIdentifier);
    if (
      !freshClient ||
      freshClient.commitmentVersion !== client.commitmentVersion
    ) {
      await this.auditLogger.log({
        eventType: "recovery_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "CONCURRENT_RECOVERY" },
      });
      return { success: false, error: "recovery_failed" };
    }

    await this.repository.update(reactivatedClient);

    // Reset failed attempts
    await this.recoveryHashStore.resetAttempts(request.clientIdentifier);

    // BA11: Generate new recovery phrase and store new hash (old phrase is invalidated)
    let newRecoveryWords: readonly string[] | undefined;
    if (this.phraseGenerator) {
      const newPhrase = this.phraseGenerator.generate(this.config.wordCount);
      const newWords = newPhrase.toDisplayString().split(" ");
      const newHash = await this.recoveryVerifier.deriveHash(
        newWords,
        request.clientIdentifier,
        this.config,
      );
      await this.recoveryHashStore.storeHash(request.clientIdentifier, newHash);
      newRecoveryWords = Object.freeze([...newWords]);
    }

    // Invalidate old tokens and challenges
    try {
      await this.tokenInvalidator.invalidateAllForClient(request.clientIdentifier);
    } catch {
      // Best effort
    }
    try {
      await this.challengeInvalidator.invalidateAllForClient(request.clientIdentifier);
    } catch {
      // Best effort
    }

    // Publish event
    try {
      await this.eventPublisher.publish(
        new ClientRecovered(request.clientIdentifier, "phrase", Date.now()),
      );
    } catch {
      // Event publishing is fire-and-forget
    }

    await this.auditLogger.log({
      eventType: "client_recovered",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      metadata: { method: "phrase" },
    });

    return {
      success: true,
      ...(newRecoveryWords ? { newRecoveryWords } : {}),
    };
  }
}
