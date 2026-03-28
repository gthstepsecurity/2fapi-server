// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { EnrollClient, EnrollClientRequest, EnrollClientResponse } from "../../domain/port/incoming/enroll-client.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { RateLimiter } from "../../domain/port/outgoing/rate-limiter.js";
import type { RecoveryHashStore } from "../../domain/port/outgoing/recovery-hash-store.js";
import type { EnrollmentPolicy } from "../../domain/service/enrollment-policy.js";
import type { RecoveryPhraseGenerator } from "../../domain/service/recovery-phrase-generator.js";
import type { RecoveryVerifier } from "../../domain/service/recovery-verifier.js";
import type { RecoveryConfig } from "../../domain/model/recovery-config.js";
import { Client } from "../../domain/model/client.js";
import { Commitment } from "../../domain/model/commitment.js";
import { ClientEnrolled } from "../../domain/event/client-enrolled.js";
import { constantTimeEqual } from "../../../shared/constant-time.js";

export class EnrollClientUseCase implements EnrollClient {
  constructor(
    private readonly policy: EnrollmentPolicy,
    private readonly repository: ClientRepository,
    private readonly idGenerator: IdGenerator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly rateLimiter: RateLimiter,
    private readonly phraseGenerator?: RecoveryPhraseGenerator,
    private readonly recoveryVerifier?: RecoveryVerifier,
    private readonly recoveryHashStore?: RecoveryHashStore,
    private readonly recoveryConfig?: RecoveryConfig,
  ) {}

  async execute(request: EnrollClientRequest): Promise<EnrollClientResponse> {
    const allowed = await this.rateLimiter.isAllowed(request.clientIdentifier);
    if (!allowed) {
      await this.auditLogger.log({
        eventType: "enrollment_failed",
        timestamp: new Date(),
        metadata: { reason: "RATE_LIMITED" },
      });
      return { success: false, error: "enrollment_failed" };
    }

    // Issue #1 — Timing oracle mitigation: always execute ALL expensive operations
    // (validation, ID generation, commitment construction, client construction)
    // regardless of whether the client already exists, so that all code paths
    // have indistinguishable execution times.

    const validationError = this.policy.validate(
      request.commitmentBytes,
      request.proofOfPossession,
      request.clientIdentifier,
    );

    const clientId = this.idGenerator.generate();
    let commitment: Commitment | null = null;
    let client: Client | null = null;
    try {
      commitment = Commitment.fromBytes(request.commitmentBytes);
      client = Client.register(clientId, request.clientIdentifier, commitment);
    } catch {
      // Construction may fail for invalid inputs; this is expected.
      // The actual error is reported via validationError below.
    }

    if (validationError || commitment === null || client === null) {
      await this.auditLogger.log({
        eventType: "enrollment_failed",
        timestamp: new Date(),
        metadata: { reason: validationError?.code ?? "INVALID_INPUT" },
      });
      return { success: false, error: "enrollment_failed" };
    }

    const existingClient = await this.repository.findByIdentifier(request.clientIdentifier);
    if (existingClient) {
      // BA09: Allow re-enrollment when client is revoked — treat as fresh enrollment
      // by reconstituting the existing client with a new commitment and active status.
      if (existingClient.status === "revoked") {
        const reEnrolled = Client.reconstitute(
          existingClient.id,
          existingClient.identifier,
          commitment!,
          "active",
          existingClient.commitmentVersion + 1,
        );
        await this.repository.update(reEnrolled);
        await this.eventPublisher.publish(
          new ClientEnrolled(request.clientIdentifier, reEnrolled.id.toString()),
        );
        await this.auditLogger.log({
          eventType: "enrollment_succeeded",
          clientIdentifier: request.clientIdentifier,
          timestamp: new Date(),
          metadata: { reEnrollment: true },
        });
        const recoveryWords = await this.generateRecoveryPhrase(request.clientIdentifier);
        return {
          success: true,
          referenceId: reEnrolled.id.toString(),
          clientIdentifier: request.clientIdentifier,
          ...(recoveryWords ? { recoveryWords } : {}),
        };
      }

      if (constantTimeEqual(existingClient.commitment.toBytes(), commitment!.toBytes())) {
        // Timing oracle mitigation: execute the same save() and publish() operations
        // as the new enrollment path so both code paths are indistinguishable by timing.
        await this.repository.save(existingClient);
        await this.eventPublisher.publish(
          new ClientEnrolled(request.clientIdentifier, existingClient.id.toString()),
        );
        return {
          success: true,
          referenceId: existingClient.id.toString(),
          clientIdentifier: existingClient.identifier,
          // Idempotent re-enrollment: do NOT return recovery words
        };
      }
      await this.auditLogger.log({
        eventType: "enrollment_failed",
        timestamp: new Date(),
        metadata: { reason: "DUPLICATE_IDENTIFIER" },
      });
      return { success: false, error: "enrollment_failed" };
    }

    try {
      await this.repository.save(client!);
    } catch (error) {
      // Retry-on-conflict: if save throws (e.g., optimistic concurrency conflict),
      // re-check if another concurrent request saved a client with the same identifier.
      // If the existing client has the same commitment, treat it as idempotent success.
      // This eliminates the TOCTOU window between findByIdentifier and save.
      const retryClient = await this.repository.findByIdentifier(request.clientIdentifier);
      if (retryClient && constantTimeEqual(retryClient.commitment.toBytes(), commitment!.toBytes())) {
        // Idempotent case — concurrent enrollment with same commitment won the race.
        // Timing safety: execute save + publish to match the new enrollment path.
        try {
          await this.repository.save(retryClient);
        } catch {
          // Expected: client already exists, save may throw again — timing safety only
        }
        await this.eventPublisher.publish(
          new ClientEnrolled(request.clientIdentifier, retryClient.id.toString()),
        );
        return {
          success: true,
          referenceId: retryClient.id.toString(),
          clientIdentifier: retryClient.identifier,
        };
      }

      await this.auditLogger.log({
        eventType: "enrollment_failure",
        timestamp: new Date(),
        metadata: { reason: "SAVE_FAILED", error: error instanceof Error ? error.message : "unknown" },
      });
      return { success: false as const, error: "enrollment_failed" as const };
    }

    await this.eventPublisher.publish(
      new ClientEnrolled(request.clientIdentifier, clientId.toString()),
    );

    await this.auditLogger.log({
      eventType: "enrollment_succeeded",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
    });

    // Generate recovery phrase if recovery is configured and mode allows phrases
    const recoveryWords = await this.generateRecoveryPhrase(request.clientIdentifier);

    return {
      success: true,
      referenceId: clientId.toString(),
      clientIdentifier: request.clientIdentifier,
      ...(recoveryWords ? { recoveryWords } : {}),
    };
  }

  /**
   * Generates a recovery phrase, hashes it, stores the hash, and returns the words.
   * Only generates if recovery dependencies are provided and mode allows phrases.
   * Returns undefined if recovery is not configured or mode is external_only.
   */
  private async generateRecoveryPhrase(
    clientIdentifier: string,
  ): Promise<readonly string[] | undefined> {
    if (
      !this.phraseGenerator ||
      !this.recoveryVerifier ||
      !this.recoveryHashStore ||
      !this.recoveryConfig
    ) {
      return undefined;
    }

    // external_only mode: no recovery phrase generation
    if (this.recoveryConfig.recoveryMode === "external_only") {
      return undefined;
    }

    const phrase = this.phraseGenerator.generate(this.recoveryConfig.wordCount);
    const words = phrase.toDisplayString().split(" ");

    // Derive hash and store it
    const hash = await this.recoveryVerifier.deriveHash(
      words,
      clientIdentifier,
      this.recoveryConfig,
    );
    await this.recoveryHashStore.storeHash(clientIdentifier, hash);

    return Object.freeze([...words]);
  }
}
