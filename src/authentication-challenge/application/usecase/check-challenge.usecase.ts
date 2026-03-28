// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CheckChallenge, CheckChallengeRequest, CheckChallengeResponse } from "../../domain/port/incoming/check-challenge.js";
import type { ChallengeRepository } from "../../domain/port/outgoing/challenge-repository.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import { ChallengeId } from "../../domain/model/challenge-id.js";

/**
 * Checks whether a challenge is still valid for use in proof verification.
 *
 * Design decision: this use case intentionally does NOT verify the
 * clientIdentifier in the request. CheckChallenge is an internal driving port
 * consumed exclusively by the ZK Verification bounded context, which already
 * possesses the challengeId from a prior authenticated flow. The
 * clientIdentifier is returned in the response so the caller can perform its
 * own binding check against the proof's claimed identity.
 */
export class CheckChallengeUseCase implements CheckChallenge {
  constructor(
    private readonly challengeRepository: ChallengeRepository,
    private readonly clock: Clock,
    private readonly auditLogger: AuditLogger,
  ) {}

  async execute(request: CheckChallengeRequest): Promise<CheckChallengeResponse> {
    const challengeId = ChallengeId.fromString(request.challengeId);
    const challenge = await this.challengeRepository.findById(challengeId);

    if (!challenge) {
      await this.auditLogger.log({
        action: "challenge_expired",
        clientIdentifier: "unknown",
        timestamp: new Date(),
        details: { challengeId: request.challengeId, reason: "not_found" },
      });
      // Indistinguishable from expired
      return { valid: false, reason: "expired" };
    }

    const nowMs = this.clock.nowMs();
    if (!challenge.isValidAt(nowMs)) {
      await this.auditLogger.log({
        action: "challenge_expired",
        clientIdentifier: challenge.clientIdentifier,
        timestamp: new Date(),
        details: { challengeId: request.challengeId, reason: "expired_or_invalidated" },
      });
      return { valid: false, reason: "expired" };
    }

    return {
      valid: true,
      clientIdentifier: challenge.clientIdentifier,
      nonce: challenge.nonce.toBytes(),
      channelBinding: challenge.channelBinding.toBytes(),
    };
  }
}
