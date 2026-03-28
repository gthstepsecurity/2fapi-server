// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RequestChallenge } from "./authentication-challenge/domain/port/incoming/request-challenge.js";
import type { CheckChallenge } from "./authentication-challenge/domain/port/incoming/check-challenge.js";
import type { CredentialVerifier } from "./authentication-challenge/domain/port/outgoing/credential-verifier.js";
import type { ClientStatusChecker } from "./authentication-challenge/domain/port/outgoing/client-status-checker.js";
import type { RateLimiter } from "./authentication-challenge/domain/port/outgoing/rate-limiter.js";
import type { ChallengeRepository } from "./authentication-challenge/domain/port/outgoing/challenge-repository.js";
import type { AuditLogger } from "./authentication-challenge/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./authentication-challenge/domain/port/outgoing/event-publisher.js";
import type { Clock } from "./authentication-challenge/domain/port/outgoing/clock.js";
import { RequestChallengeUseCase } from "./authentication-challenge/application/usecase/request-challenge.usecase.js";
import { CheckChallengeUseCase } from "./authentication-challenge/application/usecase/check-challenge.usecase.js";
import { ChallengeIssuancePolicy } from "./authentication-challenge/domain/service/challenge-issuance-policy.js";
import { ProtocolVersion } from "./authentication-challenge/domain/model/protocol-version.js";
import { CryptoNonceGenerator } from "./authentication-challenge/infrastructure/adapter/outgoing/crypto-nonce-generator.js";
import { CryptoRandomIdGenerator } from "./authentication-challenge/infrastructure/adapter/outgoing/crypto-random-id-generator.js";
import { NoopRateLimiter } from "./authentication-challenge/infrastructure/adapter/outgoing/noop-rate-limiter.js";

export interface ChallengeServiceDependencies {
  readonly credentialVerifier: CredentialVerifier;
  readonly clientStatusChecker: ClientStatusChecker;
  readonly challengeRepository: ChallengeRepository;
  readonly auditLogger: AuditLogger;
  readonly eventPublisher: EventPublisher;
  readonly clock: Clock;
  readonly rateLimiter?: RateLimiter;
  readonly supportedVersions?: readonly string[];
  readonly ttlMs?: number;
  readonly legacyMigrationActive?: boolean;
  readonly initialCounter?: bigint;
}

export interface ChallengeService {
  readonly requestChallenge: RequestChallenge;
  readonly checkChallenge: CheckChallenge;
}

export function createChallengeService(deps: ChallengeServiceDependencies): ChallengeService {
  const supportedVersions = (deps.supportedVersions ?? ["1.0"]).map(
    (v) => ProtocolVersion.fromString(v),
  );
  const ttlMs = deps.ttlMs ?? 2 * 60 * 1000;
  const policy = new ChallengeIssuancePolicy(supportedVersions, deps.legacyMigrationActive ?? false);

  const requestChallenge = new RequestChallengeUseCase(
    deps.credentialVerifier,
    deps.clientStatusChecker,
    deps.rateLimiter ?? new NoopRateLimiter(),
    deps.challengeRepository,
    new CryptoNonceGenerator(deps.initialCounter),
    new CryptoRandomIdGenerator(),
    deps.auditLogger,
    deps.eventPublisher,
    deps.clock,
    policy,
    ttlMs,
  );

  const checkChallenge = new CheckChallengeUseCase(
    deps.challengeRepository,
    deps.clock,
    deps.auditLogger,
  );

  return { requestChallenge, checkChallenge };
}
