// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// Composition root: assembles all dependencies for the recovery service.
// Lives at src/ root following the same pattern as other factory functions.

import type { ClientRepository } from "./client-registration/domain/port/outgoing/client-repository.js";
import type { RecoveryHashStore } from "./client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { Argon2Hasher } from "./client-registration/domain/port/outgoing/argon2-hasher.js";
import type { TokenInvalidator } from "./client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "./client-registration/domain/port/outgoing/challenge-invalidator.js";
import type { AuditLogger } from "./client-registration/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./client-registration/domain/port/outgoing/event-publisher.js";
import type { AdminAuthenticator } from "./client-registration/domain/port/outgoing/admin-authenticator.js";
import type { RecoveryConfig } from "./client-registration/domain/model/recovery-config.js";
import type { RecoverViaPhrase } from "./client-registration/domain/port/incoming/recover-via-phrase.js";
import type { ReactivateViaExternal } from "./client-registration/domain/port/incoming/reactivate-via-external.js";
import { RecoverViaPhraseUseCase } from "./client-registration/application/usecase/recover-via-phrase.usecase.js";
import { ReactivateViaExternalUseCase, type ReactivationProofVerifier } from "./client-registration/application/usecase/reactivate-via-external.usecase.js";
import { StubArgon2Hasher } from "./client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";

export interface RecoveryServiceDependencies {
  clientRepository: ClientRepository;
  recoveryHashStore: RecoveryHashStore;
  argon2Hasher: Argon2Hasher;
  tokenInvalidator: TokenInvalidator;
  challengeInvalidator: ChallengeInvalidator;
  auditLogger: AuditLogger;
  eventPublisher: EventPublisher;
  adminAuthenticator: AdminAuthenticator;
  recoveryConfig: RecoveryConfig;
  reactivationProofVerifier: ReactivationProofVerifier;
  environment?: "development" | "test" | "production";
}

export interface RecoveryService {
  recoverViaPhrase: RecoverViaPhrase;
  reactivateViaExternal: ReactivateViaExternal;
}

export function createRecoveryService(
  deps: RecoveryServiceDependencies,
): RecoveryService {
  if (deps.environment === "production") {
    if (deps.argon2Hasher instanceof StubArgon2Hasher) {
      throw new Error(
        "Argon2Hasher is required — never deploy with StubArgon2Hasher",
      );
    }
  }

  const recoverViaPhrase = new RecoverViaPhraseUseCase(
    deps.clientRepository,
    deps.recoveryHashStore,
    deps.argon2Hasher,
    deps.tokenInvalidator,
    deps.challengeInvalidator,
    deps.auditLogger,
    deps.eventPublisher,
    deps.recoveryConfig,
  );

  const reactivateViaExternal = new ReactivateViaExternalUseCase(
    deps.adminAuthenticator,
    deps.clientRepository,
    deps.recoveryHashStore,
    deps.tokenInvalidator,
    deps.challengeInvalidator,
    deps.auditLogger,
    deps.eventPublisher,
    deps.reactivationProofVerifier,
  );

  return { recoverViaPhrase, reactivateViaExternal };
}
