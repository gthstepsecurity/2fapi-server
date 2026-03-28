// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RevokeClient, RevokeClientRequest, RevokeClientResponse } from "../../domain/port/incoming/revoke-client.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { TokenInvalidator } from "../../domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { AdminAuthenticator } from "../../domain/port/outgoing/admin-authenticator.js";
import type { RevocationPolicy } from "../../domain/service/revocation-policy.js";
import { ClientRevoked } from "../../domain/event/client-revoked.js";

export class RevokeClientUseCase implements RevokeClient {
  constructor(
    private readonly policy: RevocationPolicy,
    private readonly adminAuthenticator: AdminAuthenticator,
    private readonly repository: ClientRepository,
    private readonly tokenInvalidator: TokenInvalidator,
    private readonly challengeInvalidator: ChallengeInvalidator,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
  ) {}

  async execute(request: RevokeClientRequest): Promise<RevokeClientResponse> {
    const validationError = this.policy.validate(request.adminIdentity);
    if (validationError) {
      await this.auditLogger.log({
        eventType: "revocation_failed",
        timestamp: new Date(),
        metadata: { reason: validationError.code },
      });
      return { success: false, error: "revocation_failed" };
    }

    const isValidAdmin = await this.adminAuthenticator.isValidAdmin(request.adminIdentity);
    if (!isValidAdmin) {
      await this.auditLogger.log({
        eventType: "revocation_failed",
        timestamp: new Date(),
        metadata: { reason: "ADMIN_AUTH_FAILED" },
      });
      return { success: false, error: "revocation_failed" };
    }

    const client = await this.repository.findByIdentifier(request.clientIdentifier);

    if (!client) {
      // Indistinguishable from success to prevent client enumeration
      await this.auditLogger.log({
        eventType: "revocation_no_such_client",
        timestamp: new Date(),
        metadata: { adminIdentity: request.adminIdentity },
      });
      return { success: true };
    }

    if (client.status === "revoked") {
      // Idempotent: already revoked
      await this.auditLogger.log({
        eventType: "client_already_revoked",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: { adminIdentity: request.adminIdentity },
      });
      return { success: true };
    }

    const revokedClient = client.revoke();
    await this.repository.update(revokedClient);

    // Invalidate tokens and challenges (best-effort, fire-and-forget for event publishing)
    await this.tokenInvalidator.invalidateAllForClient(request.clientIdentifier);
    await this.challengeInvalidator.invalidateAllForClient(request.clientIdentifier);

    try {
      await this.eventPublisher.publish(
        new ClientRevoked(request.clientIdentifier, request.adminIdentity),
      );
    } catch {
      // Event publishing is fire-and-forget — revocation is already committed.
      // Log a critical audit entry so operators know the event was lost.
      await this.auditLogger.log({
        eventType: "revocation_event_publish_failed",
        clientIdentifier: request.clientIdentifier,
        timestamp: new Date(),
        metadata: {
          severity: "CRITICAL",
          adminIdentity: request.adminIdentity,
          note: "ClientRevoked event lost; tokens and challenges were already invalidated directly",
        },
      });
    }

    await this.auditLogger.log({
      eventType: "client_revoked",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      metadata: { adminIdentity: request.adminIdentity },
    });

    return { success: true };
  }
}
