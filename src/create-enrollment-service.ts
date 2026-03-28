// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// Composition root: assembles all dependencies for the enrollment service.
// Lives at src/ root as the library's primary entry point for consumers.
// Alternative location: client-registration/infrastructure/config/

import type { ClientRepository } from "./client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "./client-registration/domain/port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "./client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import type { IdGenerator } from "./client-registration/domain/port/outgoing/id-generator.js";
import type { AuditLogger } from "./client-registration/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./client-registration/domain/port/outgoing/event-publisher.js";
import type { RateLimiter } from "./client-registration/domain/port/outgoing/rate-limiter.js";
import type { RecoveryHashStore } from "./client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { Argon2Hasher } from "./client-registration/domain/port/outgoing/argon2-hasher.js";
import type { Bip39WordlistProvider } from "./client-registration/domain/model/bip39-wordlist.js";
import type { SecureRandomProvider } from "./client-registration/domain/port/outgoing/secure-random-provider.js";
import type { EnrollClient } from "./client-registration/domain/port/incoming/enroll-client.js";
import type { RecoveryConfig } from "./client-registration/domain/model/recovery-config.js";
import { EnrollmentPolicy } from "./client-registration/domain/service/enrollment-policy.js";
import { RecoveryPhraseGenerator } from "./client-registration/domain/service/recovery-phrase-generator.js";
import { RecoveryVerifier } from "./client-registration/domain/service/recovery-verifier.js";
import { EnrollClientUseCase } from "./client-registration/application/usecase/enroll-client.usecase.js";

export interface EnrollmentServiceDependencies {
  clientRepository: ClientRepository;
  commitmentVerifier: CommitmentVerifier;
  proofOfPossessionVerifier: ProofOfPossessionVerifier;
  idGenerator: IdGenerator;
  auditLogger: AuditLogger;
  eventPublisher: EventPublisher;
  rateLimiter: RateLimiter;
  // Optional recovery dependencies — if provided, enrollment generates recovery phrases
  recoveryHashStore?: RecoveryHashStore;
  argon2Hasher?: Argon2Hasher;
  wordlistProvider?: Bip39WordlistProvider;
  secureRandomProvider?: SecureRandomProvider;
  recoveryConfig?: RecoveryConfig;
}

export function createEnrollmentService(
  deps: EnrollmentServiceDependencies,
): EnrollClient {
  const policy = new EnrollmentPolicy(
    deps.commitmentVerifier,
    deps.proofOfPossessionVerifier,
  );

  // Build optional recovery dependencies
  let phraseGenerator: RecoveryPhraseGenerator | undefined;
  let recoveryVerifier: RecoveryVerifier | undefined;

  if (
    deps.recoveryHashStore &&
    deps.argon2Hasher &&
    deps.wordlistProvider &&
    deps.secureRandomProvider &&
    deps.recoveryConfig
  ) {
    phraseGenerator = new RecoveryPhraseGenerator(
      deps.wordlistProvider,
      deps.secureRandomProvider,
    );
    recoveryVerifier = new RecoveryVerifier(deps.argon2Hasher);
  }

  return new EnrollClientUseCase(
    policy,
    deps.clientRepository,
    deps.idGenerator,
    deps.auditLogger,
    deps.eventPublisher,
    deps.rateLimiter,
    phraseGenerator,
    recoveryVerifier,
    deps.recoveryHashStore,
    deps.recoveryConfig,
  );
}
