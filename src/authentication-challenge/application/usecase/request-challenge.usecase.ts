// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RequestChallenge, RequestChallengeRequest, RequestChallengeResponse } from "../../domain/port/incoming/request-challenge.js";
import type { CredentialVerifier } from "../../domain/port/outgoing/credential-verifier.js";
import type { ClientStatusChecker } from "../../domain/port/outgoing/client-status-checker.js";
import type { RateLimiter } from "../../domain/port/outgoing/rate-limiter.js";
import type { ChallengeRepository } from "../../domain/port/outgoing/challenge-repository.js";
import type { NonceGenerator } from "../../domain/port/outgoing/nonce-generator.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import { ChallengeIssuancePolicy } from "../../domain/service/challenge-issuance-policy.js";
import { Challenge } from "../../domain/model/challenge.js";
import { ChallengeId } from "../../domain/model/challenge-id.js";
import { ChannelBinding } from "../../domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../domain/model/challenge-expiry.js";
import { ProtocolVersion } from "../../domain/model/protocol-version.js";
import { FirstFactorType } from "../../domain/model/first-factor-type.js";
import { ChallengeIssued } from "../../domain/event/challenge-issued.js";
import { ChallengeInvalidated } from "../../domain/event/challenge-invalidated.js";

export class RequestChallengeUseCase implements RequestChallenge {
  constructor(
    private readonly credentialVerifier: CredentialVerifier,
    private readonly clientStatusChecker: ClientStatusChecker,
    private readonly rateLimiter: RateLimiter,
    private readonly challengeRepository: ChallengeRepository,
    private readonly nonceGenerator: NonceGenerator,
    private readonly idGenerator: IdGenerator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly clock: Clock,
    private readonly policy: ChallengeIssuancePolicy,
    private readonly ttlMs: number,
  ) {}

  async execute(request: RequestChallengeRequest): Promise<RequestChallengeResponse> {
    // Validate clientIdentifier length
    const identifierByteLength = new TextEncoder().encode(request.clientIdentifier).length;
    if (identifierByteLength === 0 || identifierByteLength > 256) {
      await this.auditLogger.log({
        action: "challenge_refused",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { reason: "invalid_client_identifier" },
      });
      return { success: false, error: "challenge_refused" };
    }

    const requestedVersion = request.protocolVersion
      ? ProtocolVersion.fromString(request.protocolVersion)
      : ProtocolVersion.fromString("1.0");

    // Rate limiting check first (before any expensive operation)
    const allowed = await this.rateLimiter.isAllowed(request.clientIdentifier);
    if (!allowed) {
      await this.auditLogger.log({
        action: "challenge_refused",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { reason: "rate_limited" },
      });
      return { success: false, error: "rate_limited" };
    }

    // Verify credential (first factor) — always execute to prevent timing oracle
    const credentialResult = await this.credentialVerifier.verify(
      request.clientIdentifier,
      request.credential,
    );

    // Check lockout status — always execute to prevent timing oracle
    const lockoutInfo = await this.clientStatusChecker.getLockoutInfo(request.clientIdentifier);

    // Policy validation
    const policyError = this.policy.validate({
      credentialValid: credentialResult.valid,
      clientStatus: credentialResult.clientStatus,
      isLockedOut: lockoutInfo.isLockedOut,
      requestedVersion,
      isLegacyApiKey: credentialResult.isLegacyApiKey,
    });

    if (policyError) {
      // Record failed attempt for credential-related failures
      if (policyError.code === "INVALID_CREDENTIAL") {
        await this.clientStatusChecker.recordFailedAttempt(request.clientIdentifier);
      }

      await this.auditLogger.log({
        action: "challenge_refused",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { reason: policyError.code },
      });

      // Timing oracle mitigation: execute the same async operations as the
      // success path so both code paths have approximately the same number
      // of async operations and indistinguishable timing characteristics.
      // Results are discarded — these calls exist solely for timing parity.
      try {
        await this.challengeRepository.capacityPercentage();
        await this.challengeRepository.findPendingByClientIdentifier(request.clientIdentifier);
        this.nonceGenerator.generate();
      } catch {
        // Ignored — timing safety only
      }

      // Map domain errors to indistinguishable public responses
      if (policyError.code === "UNSUPPORTED_VERSION") {
        return {
          success: false,
          error: "unsupported_protocol_version",
          supportedVersions: policyError.supportedVersions ?? [],
        };
      }
      // INVALID_CREDENTIAL, CLIENT_REVOKED, CLIENT_SUSPENDED, CLIENT_UNKNOWN, CLIENT_LOCKED_OUT, LEGACY_NOT_ALLOWED
      // All return the same indistinguishable response to prevent account enumeration
      return { success: false, error: "challenge_refused" };
    }

    // Check repository capacity before issuing
    const capacity = await this.challengeRepository.capacityPercentage();
    if (capacity >= 100) {
      await this.auditLogger.log({
        action: "challenge_refused",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { reason: "service_unavailable" },
      });
      return { success: false, error: "service_unavailable" };
    }

    // Invalidate previous pending challenge (atomic: invalidate old + issue new)
    const previousChallenge = await this.challengeRepository.findPendingByClientIdentifier(
      request.clientIdentifier,
    );
    if (previousChallenge) {
      const invalidated = previousChallenge.invalidate();
      await this.challengeRepository.save(invalidated);
      await this.auditLogger.log({
        action: "challenge_invalidated",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { challengeId: previousChallenge.id.value },
      });
      await this.eventPublisher.publish(
        new ChallengeInvalidated(request.clientIdentifier, previousChallenge.id.value),
      );
    }

    // Issue new challenge
    const nowMs = this.clock.nowMs();
    const challengeId = ChallengeId.fromString(this.idGenerator.generate());
    const nonce = this.nonceGenerator.generate();
    let channelBinding: ChannelBinding;
    try {
      channelBinding = ChannelBinding.fromTlsExporter(request.channelBinding);
    } catch {
      await this.auditLogger.log({
        action: "challenge_refused",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        details: { reason: "invalid_channel_binding" },
      });
      return { success: false, error: "challenge_refused" };
    }
    const expiry = ChallengeExpiry.create(nowMs, this.ttlMs);
    const firstFactorType = credentialResult.isLegacyApiKey
      ? FirstFactorType.LEGACY_API_KEY
      : FirstFactorType.ZKP;

    const challenge = Challenge.issue(
      challengeId,
      request.clientIdentifier,
      nonce,
      channelBinding,
      expiry,
      firstFactorType,
    );

    await this.challengeRepository.save(challenge);

    await this.auditLogger.log({
      action: "challenge_issued",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      details: {
        challengeId: challengeId.value,
        firstFactorType,
        legacyFirstFactor: credentialResult.isLegacyApiKey,
      },
    });

    await this.eventPublisher.publish(
      new ChallengeIssued(request.clientIdentifier, challengeId.value, nowMs + this.ttlMs),
    );

    return {
      success: true,
      challengeId: challengeId.value,
      nonce: nonce.toBytes(),
      channelBinding: channelBinding.toBytes(),
      expiresAtMs: nowMs + this.ttlMs,
      protocolVersion: requestedVersion.value,
      legacyFirstFactor: credentialResult.isLegacyApiKey,
    };
  }
}
