// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// Composition root: assembles all dependencies for the lifecycle service (revocation + rotation).
// Lives at src/ root following the same pattern as create-enrollment-service.ts.

import type { ClientRepository } from "./client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "./client-registration/domain/port/outgoing/commitment-verifier.js";
import type { RotationProofVerifier } from "./client-registration/domain/port/outgoing/rotation-proof-verifier.js";
import type { TokenInvalidator } from "./client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "./client-registration/domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "./client-registration/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./client-registration/domain/port/outgoing/event-publisher.js";
import type { AdminAuthenticator } from "./client-registration/domain/port/outgoing/admin-authenticator.js";
import type { RateLimiter } from "./client-registration/domain/port/outgoing/rate-limiter.js";
import type { RevokeClient } from "./client-registration/domain/port/incoming/revoke-client.js";
import type { RotateCommitment } from "./client-registration/domain/port/incoming/rotate-commitment.js";
import { RevocationPolicy } from "./client-registration/domain/service/revocation-policy.js";
import { RotationPolicy } from "./client-registration/domain/service/rotation-policy.js";
import { RevokeClientUseCase } from "./client-registration/application/usecase/revoke-client.usecase.js";
import { RotateCommitmentUseCase } from "./client-registration/application/usecase/rotate-commitment.usecase.js";
import { StubAdminAuthenticator } from "./client-registration/infrastructure/adapter/outgoing/stub-admin-authenticator.js";

export interface LifecycleServiceDependencies {
  clientRepository: ClientRepository;
  commitmentVerifier: CommitmentVerifier;
  rotationProofVerifier: RotationProofVerifier;
  tokenInvalidator: TokenInvalidator;
  challengeInvalidator: ChallengeInvalidator;
  auditLogger: AuditLogger;
  eventPublisher: EventPublisher;
  adminAuthenticator: AdminAuthenticator;
  rateLimiter: RateLimiter;
  environment?: "development" | "test" | "production";
}

export interface LifecycleService {
  revokeClient: RevokeClient;
  rotateCommitment: RotateCommitment;
}

export function createLifecycleService(
  deps: LifecycleServiceDependencies,
): LifecycleService {
  if (deps.environment === "production") {
    if (!deps.adminAuthenticator) {
      throw new Error(
        "AdminAuthenticator is required — never deploy with StubAdminAuthenticator",
      );
    }
    if (deps.adminAuthenticator instanceof StubAdminAuthenticator) {
      throw new Error(
        "AdminAuthenticator is required — never deploy with StubAdminAuthenticator",
      );
    }
  }

  const revocationPolicy = new RevocationPolicy();
  const rotationPolicy = new RotationPolicy(
    deps.commitmentVerifier,
    deps.rotationProofVerifier,
  );

  const revokeClient = new RevokeClientUseCase(
    revocationPolicy,
    deps.adminAuthenticator,
    deps.clientRepository,
    deps.tokenInvalidator,
    deps.challengeInvalidator,
    deps.auditLogger,
    deps.eventPublisher,
  );

  const rotateCommitment = new RotateCommitmentUseCase(
    rotationPolicy,
    deps.clientRepository,
    deps.tokenInvalidator,
    deps.challengeInvalidator,
    deps.auditLogger,
    deps.eventPublisher,
    deps.rateLimiter,
  );

  return { revokeClient, rotateCommitment };
}
