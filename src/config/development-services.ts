// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Development service factory.
 *
 * Creates all services using in-memory/stub adapters.
 * This is the default mode for development and testing.
 * No external infrastructure (PostgreSQL, Redis) is required.
 */

import type { EnrollClient } from "../client-registration/domain/port/incoming/enroll-client.js";
import type { RequestChallenge } from "../authentication-challenge/domain/port/incoming/request-challenge.js";
import type { CheckChallenge } from "../authentication-challenge/domain/port/incoming/check-challenge.js";
import type { VerifyProof } from "../zk-verification/domain/port/incoming/verify-proof.js";
import type { IssueToken } from "../api-access-control/domain/port/incoming/issue-token.js";
import type { ValidateToken } from "../api-access-control/domain/port/incoming/validate-token.js";
import type { RevokeClient } from "../client-registration/domain/port/incoming/revoke-client.js";
import type { RotateCommitment } from "../client-registration/domain/port/incoming/rotate-commitment.js";
import type { RecoverViaPhrase } from "../client-registration/domain/port/incoming/recover-via-phrase.js";
import type { ReactivateViaExternal } from "../client-registration/domain/port/incoming/reactivate-via-external.js";
import type { RecordFailedAttempt } from "../security-monitoring/domain/port/incoming/record-failed-attempt.js";
import type { RecordSuccessfulAuth } from "../security-monitoring/domain/port/incoming/record-successful-auth.js";
import type { CheckLockoutStatus } from "../security-monitoring/domain/port/incoming/check-lockout-status.js";
import type { RecordAuditEvent } from "../security-monitoring/domain/port/incoming/record-audit-event.js";
import type { DetectAnomalies } from "../security-monitoring/domain/port/incoming/detect-anomalies.js";
import type { BatchProofVerifier } from "../zk-verification/domain/port/outgoing/batch-proof-verifier.js";
import type { InputHardeningPolicy } from "../zk-verification/domain/service/input-hardening-policy.js";
import type { GlobalRateLimiter } from "../shared/global-rate-limiter.js";
import type { IpRateLimiter } from "../api-gateway/middleware/ip-rate-limiter.js";

// In-memory / Stub adapters
import { InMemoryClientRepository } from "../client-registration/infrastructure/adapter/outgoing/in-memory-client-repository.js";
import { StubCommitmentVerifier } from "../client-registration/infrastructure/adapter/outgoing/stub-commitment-verifier.js";
import { StubProofOfPossessionVerifier } from "../client-registration/infrastructure/adapter/outgoing/stub-proof-of-possession-verifier.js";
import { CryptoRandomIdGenerator } from "../client-registration/infrastructure/adapter/outgoing/crypto-random-id-generator.js";
import { ConsoleAuditLogger } from "../client-registration/infrastructure/adapter/outgoing/console-audit-logger.js";
import { NoopEventPublisher } from "../client-registration/infrastructure/adapter/outgoing/noop-event-publisher.js";
import { StubTokenInvalidator } from "../client-registration/infrastructure/adapter/outgoing/stub-token-invalidator.js";
import { StubChallengeInvalidator } from "../client-registration/infrastructure/adapter/outgoing/stub-challenge-invalidator.js";
import { StubRotationProofVerifier } from "../client-registration/infrastructure/adapter/outgoing/stub-rotation-proof-verifier.js";
import { StubAdminAuthenticator } from "../client-registration/infrastructure/adapter/outgoing/stub-admin-authenticator.js";
import { InMemoryRecoveryHashStore } from "../client-registration/infrastructure/adapter/outgoing/in-memory-recovery-hash-store.js";
import { StubArgon2Hasher } from "../client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";
import { StubBip39WordlistProvider } from "../client-registration/infrastructure/adapter/outgoing/stub-bip39-wordlist-provider.js";
import { CryptoSecureRandomProvider } from "../client-registration/infrastructure/adapter/outgoing/crypto-secure-random-provider.js";
import { InMemoryChallengeRepository } from "../authentication-challenge/infrastructure/adapter/outgoing/in-memory-challenge-repository.js";
import { StubCredentialVerifier } from "../authentication-challenge/infrastructure/adapter/outgoing/stub-credential-verifier.js";
import { StubClientStatusChecker } from "../authentication-challenge/infrastructure/adapter/outgoing/stub-client-status-checker.js";
import { MonotonicClock } from "../authentication-challenge/infrastructure/adapter/outgoing/monotonic-clock.js";
import { StubElementValidator } from "../zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
import { StubCommitmentLookup } from "../zk-verification/infrastructure/adapter/outgoing/stub-commitment-lookup.js";
import { StubChallengeConsumer } from "../zk-verification/infrastructure/adapter/outgoing/stub-challenge-consumer.js";
import { StubProofEquationVerifier } from "../zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
import { StubTranscriptHasher } from "../zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
import { StubFailedAttemptTracker } from "../zk-verification/infrastructure/adapter/outgoing/stub-failed-attempt-tracker.js";
import { StubTokenSigner } from "../api-access-control/infrastructure/adapter/outgoing/stub-token-signer.js";
import { StubTokenVerifier } from "../api-access-control/infrastructure/adapter/outgoing/stub-token-verifier.js";
import { StubClientStatusChecker as AccessControlStubClientStatusChecker } from "../api-access-control/infrastructure/adapter/outgoing/stub-client-status-checker.js";
import { StubAuthorizationChecker } from "../api-access-control/infrastructure/adapter/outgoing/stub-authorization-checker.js";
import { InMemoryVerificationReceiptStore } from "../api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";
import { InMemoryAttemptCounterStore } from "../security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
import { InMemoryAuditLogStore } from "../security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { InMemoryAnomalyBaselineStore } from "../security-monitoring/infrastructure/adapter/outgoing/in-memory-anomaly-baseline-store.js";
import { StubAlertDispatcher } from "../security-monitoring/infrastructure/adapter/outgoing/stub-alert-dispatcher.js";
import { NoopEventPublisher as MonitoringNoopEventPublisher } from "../security-monitoring/infrastructure/adapter/outgoing/noop-event-publisher.js";
import { InMemoryGlobalRateLimiter } from "../shared/global-rate-limiter.js";
import { InMemoryIpRateLimiter } from "../api-gateway/middleware/ip-rate-limiter.js";

// Factories
import { createEnrollmentService } from "../create-enrollment-service.js";
import { createChallengeService } from "../create-challenge-service.js";
import { createVerificationService } from "../create-verification-service.js";
import { createAccessControlService } from "../create-access-control-service.js";
import { createMonitoringService } from "../create-monitoring-service.js";
import { createLifecycleService } from "../create-lifecycle-service.js";
import { createRecoveryService } from "../create-recovery-service.js";

// Domain models
import { RecoveryConfig } from "../client-registration/domain/model/recovery-config.js";

export interface AllServices {
  readonly enrollClient: EnrollClient;
  readonly requestChallenge: RequestChallenge;
  readonly checkChallenge: CheckChallenge;
  readonly verifyProof: VerifyProof;
  readonly issueToken: IssueToken;
  readonly validateToken: ValidateToken;
  readonly revokeClient: RevokeClient;
  readonly rotateCommitment: RotateCommitment;
  readonly recoverViaPhrase: RecoverViaPhrase;
  readonly reactivateViaExternal: ReactivateViaExternal;
  readonly recordFailedAttempt: RecordFailedAttempt;
  readonly recordSuccessfulAuth: RecordSuccessfulAuth;
  readonly checkLockoutStatus: CheckLockoutStatus;
  readonly recordAuditEvent: RecordAuditEvent;
  readonly detectAnomalies: DetectAnomalies;
  readonly batchVerifier: BatchProofVerifier;
  readonly inputHardeningPolicy: InputHardeningPolicy;
  readonly globalRateLimiter: GlobalRateLimiter;
  readonly ipRateLimiter: IpRateLimiter;
}

/**
 * Creates all services using in-memory/stub adapters.
 * Suitable for development and testing environments.
 */
export function createDevelopmentServices(): AllServices {
  // Shared infrastructure (in-memory)
  const clientRepository = new InMemoryClientRepository();
  const challengeRepository = new InMemoryChallengeRepository();
  const clock = new MonotonicClock();
  const recoveryConfig = RecoveryConfig.defaults();

  // Client Registration dependencies
  const commitmentVerifier = new StubCommitmentVerifier();
  const proofOfPossessionVerifier = new StubProofOfPossessionVerifier(true);
  const enrollIdGenerator = new CryptoRandomIdGenerator();
  const auditLogger = new ConsoleAuditLogger();
  const eventPublisher = new NoopEventPublisher();
  const recoveryHashStore = new InMemoryRecoveryHashStore();
  const argon2Hasher = new StubArgon2Hasher();
  const wordlistProvider = new StubBip39WordlistProvider();
  const secureRandomProvider = new CryptoSecureRandomProvider();

  // Build enrollment service
  const enrollClient = createEnrollmentService({
    clientRepository,
    commitmentVerifier,
    proofOfPossessionVerifier,
    idGenerator: enrollIdGenerator,
    auditLogger,
    eventPublisher,
    rateLimiter: { isAllowed: async () => true },
    recoveryHashStore,
    argon2Hasher,
    wordlistProvider,
    secureRandomProvider,
    recoveryConfig,
  });

  // Build challenge service
  const credentialVerifier = new StubCredentialVerifier({
    valid: true,
    clientIdentifier: "any",
    clientStatus: "active",
    isLegacyApiKey: false,
  });
  const clientStatusChecker = new StubClientStatusChecker({
    isLockedOut: false,
    failedAttempts: 0,
  });
  // Challenge BC has its own AuditLogger interface (AuditEntry, not AuditEvent)
  const challengeAuditLogger = { log: async () => {} };
  const challengeEventPublisher = { publish: async () => {} };
  const challengeService = createChallengeService({
    credentialVerifier,
    clientStatusChecker,
    challengeRepository,
    auditLogger: challengeAuditLogger,
    eventPublisher: challengeEventPublisher,
    clock,
  });

  // Build verification service
  const elementValidator = new StubElementValidator();
  const commitmentLookup = new StubCommitmentLookup();
  const challengeConsumer = new StubChallengeConsumer();
  const transcriptHasher = new StubTranscriptHasher();
  const proofEquationVerifier = new StubProofEquationVerifier(true);
  const failedAttemptTracker = new StubFailedAttemptTracker();
  const generatorG = new Uint8Array(32).fill(0x01);
  const generatorH = new Uint8Array(32).fill(0x02);
  // Verification BC has its own AuditLogger interface
  const verificationAuditLogger = { log: async () => {} };
  const verificationEventPublisher = { publish: async () => {} };

  const verificationService = createVerificationService({
    challengeConsumer,
    commitmentLookup,
    elementValidator,
    transcriptHasher,
    proofEquationVerifier,
    failedAttemptTracker,
    auditLogger: verificationAuditLogger,
    eventPublisher: verificationEventPublisher,
    clock,
    generatorG,
    generatorH,
    environment: "development",
  });

  // Build access control service
  const tokenSigner = new StubTokenSigner();
  const tokenVerifier = new StubTokenVerifier();
  const accessControlClientStatus = new AccessControlStubClientStatusChecker(true);
  const authorizationChecker = new StubAuthorizationChecker(true);
  const receiptStore = new InMemoryVerificationReceiptStore();
  const accessControlIdGenerator = {
    generate: () => `tok-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  };

  const accessControlService = createAccessControlService({
    tokenSigner,
    tokenVerifier,
    clientStatusChecker: accessControlClientStatus,
    authorizationChecker,
    auditLogger: { log: async () => {} },
    eventPublisher: { publish: async () => {} },
    clock: { nowMs: () => Date.now() },
    idGenerator: accessControlIdGenerator,
    receiptStore,
  });

  // Build monitoring service
  const counterStore = new InMemoryAttemptCounterStore();
  const auditLogStore = new InMemoryAuditLogStore();
  const baselineStore = new InMemoryAnomalyBaselineStore();
  const alertDispatcher = new StubAlertDispatcher();
  const monitoringEventPublisher = new MonitoringNoopEventPublisher();
  const monitoringIdGenerator = {
    generate: () => `mon-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  };

  const monitoringService = createMonitoringService({
    counterStore,
    auditLogStore,
    baselineStore,
    alertDispatcher,
    eventPublisher: monitoringEventPublisher,
    clock: { nowMs: () => Date.now() },
    idGenerator: monitoringIdGenerator,
  });

  // Build lifecycle service (revocation + rotation)
  const adminAuth = new StubAdminAuthenticator();
  const tokenInvalidator = new StubTokenInvalidator();
  const challengeInvalidator = new StubChallengeInvalidator();
  const rotationProofVerifier = new StubRotationProofVerifier(true);

  const lifecycleService = createLifecycleService({
    clientRepository,
    commitmentVerifier,
    rotationProofVerifier,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger,
    eventPublisher,
    adminAuthenticator: adminAuth,
    rateLimiter: { isAllowed: async () => true },
    environment: "development",
  });

  // Build recovery service
  const reactivationProofVerifier = { verify: () => true };
  const recoveryService = createRecoveryService({
    clientRepository,
    recoveryHashStore,
    argon2Hasher,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger,
    eventPublisher,
    adminAuthenticator: adminAuth,
    recoveryConfig,
    reactivationProofVerifier,
    environment: "development",
  });

  // Rate limiters
  const globalRateLimiter = new InMemoryGlobalRateLimiter(1000, 1000);
  const ipRateLimiter = new InMemoryIpRateLimiter(100, 1000);

  return {
    enrollClient,
    requestChallenge: challengeService.requestChallenge,
    checkChallenge: challengeService.checkChallenge,
    verifyProof: verificationService.verifyProof,
    issueToken: accessControlService.issueToken,
    validateToken: accessControlService.validateToken,
    revokeClient: lifecycleService.revokeClient,
    rotateCommitment: lifecycleService.rotateCommitment,
    recoverViaPhrase: recoveryService.recoverViaPhrase,
    reactivateViaExternal: recoveryService.reactivateViaExternal,
    recordFailedAttempt: monitoringService.recordFailedAttempt,
    recordSuccessfulAuth: monitoringService.recordSuccessfulAuth,
    checkLockoutStatus: monitoringService.checkLockoutStatus,
    recordAuditEvent: monitoringService.recordAuditEvent,
    detectAnomalies: monitoringService.detectAnomalies,
    batchVerifier: verificationService.batchVerifier,
    inputHardeningPolicy: verificationService.inputHardeningPolicy,
    globalRateLimiter,
    ipRateLimiter,
  };
}
