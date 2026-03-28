// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ReactivateViaExternal,
  ReactivateViaExternalRequest,
  ReactivateViaExternalResponse,
} from "../../domain/port/incoming/reactivate-via-external.js";
import type { AdminAuthenticator } from "../../domain/port/outgoing/admin-authenticator.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { RecoveryHashStore } from "../../domain/port/outgoing/recovery-hash-store.js";
import type { TokenInvalidator } from "../../domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
/**
 * Verifies proof of possession for a new commitment during reactivation.
 * BD08: Admin must provide cryptographic proof to prevent impersonation.
 */
export interface ReactivationProofVerifier {
  verify(newCommitmentBytes: Uint8Array, proofBytes: Uint8Array): boolean;
}
import { Commitment } from "../../domain/model/commitment.js";
import { ClientReactivated } from "../../domain/event/client-reactivated.js";

export class ReactivateViaExternalUseCase implements ReactivateViaExternal {
  constructor(
    private readonly adminAuthenticator: AdminAuthenticator,
    private readonly repository: ClientRepository,
    private readonly recoveryHashStore: RecoveryHashStore,
    private readonly tokenInvalidator: TokenInvalidator,
    private readonly challengeInvalidator: ChallengeInvalidator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly proofVerifier: ReactivationProofVerifier,
  ) {}

  async execute(request: ReactivateViaExternalRequest): Promise<ReactivateViaExternalResponse> {
    // Verify admin credentials first (before any client lookup)
    if (!request.adminIdentity || request.adminIdentity.trim().length === 0) {
      await this.auditLogger.log({
        eventType: "reactivation_failed",
        timestamp: new Date(),
        metadata: { reason: "MISSING_ADMIN_IDENTITY" },
      });
      return { success: false, error: "reactivation_failed" };
    }

    const isValidAdmin = await this.adminAuthenticator.isValidAdmin(request.adminIdentity);
    if (!isValidAdmin) {
      await this.auditLogger.log({
        eventType: "reactivation_failed",
        timestamp: new Date(),
        metadata: { reason: "ADMIN_AUTH_FAILED" },
      });
      return { success: false, error: "reactivation_failed" };
    }

    // Find client
    const client = await this.repository.findByIdentifier(request.clientIdentifier);

    if (!client) {
      await this.auditLogger.log({
        eventType: "reactivation_failed",
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_FOUND", adminIdentity: request.adminIdentity },
      });
      return { success: false, error: "reactivation_failed" };
    }

    // Check client is suspended
    if (client.status !== "suspended") {
      await this.auditLogger.log({
        eventType: "reactivation_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "CLIENT_NOT_SUSPENDED", adminIdentity: request.adminIdentity },
      });
      return { success: false, error: "reactivation_failed" };
    }

    // BD08: Verify commitment proof before accepting the new commitment
    const proofValid = this.proofVerifier.verify(
      request.newCommitmentBytes,
      request.newCommitmentProofBytes,
    );
    if (!proofValid) {
      await this.auditLogger.log({
        eventType: "reactivation_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { reason: "INVALID_COMMITMENT_PROOF", adminIdentity: request.adminIdentity },
      });
      return { success: false, error: "reactivation_failed" };
    }

    // Reactivate with new commitment
    const newCommitment = Commitment.fromBytes(request.newCommitmentBytes);
    const reactivatedClient = client.reactivate(newCommitment);

    await this.repository.update(reactivatedClient);

    // Delete old recovery hash (invalidate old phrase) and reset attempts
    await this.recoveryHashStore.deleteHash(request.clientIdentifier);
    await this.recoveryHashStore.resetAttempts(request.clientIdentifier);

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
        new ClientReactivated(request.clientIdentifier, request.adminIdentity, Date.now()),
      );
    } catch {
      // Event publishing is fire-and-forget
    }

    await this.auditLogger.log({
      eventType: "client_reactivated",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      metadata: { adminIdentity: request.adminIdentity },
    });

    return { success: true };
  }
}
