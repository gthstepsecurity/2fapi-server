// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// --- Domain Models ---
export { Client } from "./client-registration/domain/model/client.js";
export { ClientId } from "./client-registration/domain/model/client-id.js";
export type { ClientStatus } from "./client-registration/domain/model/client-status.js";
export { Commitment } from "./client-registration/domain/model/commitment.js";
export { EnrollmentReceipt } from "./client-registration/domain/model/enrollment-receipt.js";
export { RecoveryPhrase } from "./client-registration/domain/model/recovery-phrase.js";
export { RecoveryConfig } from "./client-registration/domain/model/recovery-config.js";
export type { RecoveryMode, RecoveryConfigOverrides } from "./client-registration/domain/model/recovery-config.js";
export type { Bip39WordlistProvider } from "./client-registration/domain/model/bip39-wordlist.js";
export { BIP39_WORD_COUNT, BIP39_WORDLIST_CHECKSUM } from "./client-registration/domain/model/bip39-wordlist.js";

// --- Domain Events ---
export { ClientEnrolled } from "./client-registration/domain/event/client-enrolled.js";
export { ClientRevoked } from "./client-registration/domain/event/client-revoked.js";
export { CommitmentRotated } from "./client-registration/domain/event/commitment-rotated.js";
export { ClientRecovered } from "./client-registration/domain/event/client-recovered.js";
export type { RecoveryMethod } from "./client-registration/domain/event/client-recovered.js";
export { ClientReactivated } from "./client-registration/domain/event/client-reactivated.js";

// --- Domain Ports (Incoming) ---
export type { EnrollClient } from "./client-registration/domain/port/incoming/enroll-client.js";
export type {
  RevokeClient,
  RevokeClientRequest,
  RevokeClientResponse,
} from "./client-registration/domain/port/incoming/revoke-client.js";
export type {
  RotateCommitment,
  RotateCommitmentRequest,
  RotateCommitmentResponse,
} from "./client-registration/domain/port/incoming/rotate-commitment.js";
export type {
  RecoverViaPhrase,
  RecoverViaPhraseRequest,
  RecoverViaPhraseResponse,
} from "./client-registration/domain/port/incoming/recover-via-phrase.js";
export type {
  ReactivateViaExternal,
  ReactivateViaExternalRequest,
  ReactivateViaExternalResponse,
} from "./client-registration/domain/port/incoming/reactivate-via-external.js";

// --- Domain Ports (Outgoing) ---
export type { ClientRepository } from "./client-registration/domain/port/outgoing/client-repository.js";
export type { CommitmentVerifier } from "./client-registration/domain/port/outgoing/commitment-verifier.js";
export type {
  ProofOfPossessionVerifier,
  ProofOfPossessionData,
} from "./client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
export type { IdGenerator } from "./client-registration/domain/port/outgoing/id-generator.js";
export type { AuditLogger, AuditEvent } from "./client-registration/domain/port/outgoing/audit-logger.js";
export type { EventPublisher, DomainEvent } from "./client-registration/domain/port/outgoing/event-publisher.js";
export type { RateLimiter } from "./client-registration/domain/port/outgoing/rate-limiter.js";
export type { TokenInvalidator } from "./client-registration/domain/port/outgoing/token-invalidator.js";
export type { ChallengeInvalidator } from "./client-registration/domain/port/outgoing/challenge-invalidator.js";
export type { RotationProofVerifier } from "./client-registration/domain/port/outgoing/rotation-proof-verifier.js";
export type { AdminAuthenticator } from "./client-registration/domain/port/outgoing/admin-authenticator.js";
export type { RecoveryHashStore } from "./client-registration/domain/port/outgoing/recovery-hash-store.js";
export type { Argon2Hasher, Argon2Params } from "./client-registration/domain/port/outgoing/argon2-hasher.js";
export type { SecureRandomProvider } from "./client-registration/domain/port/outgoing/secure-random-provider.js";

// --- Application DTOs ---
export type { EnrollClientRequest } from "./client-registration/application/dto/enroll-client.request.js";
export type { EnrollClientResponse } from "./client-registration/application/dto/enroll-client.response.js";

// --- Domain Services ---
export { EnrollmentPolicy } from "./client-registration/domain/service/enrollment-policy.js";
export { RevocationPolicy } from "./client-registration/domain/service/revocation-policy.js";
export { RotationPolicy } from "./client-registration/domain/service/rotation-policy.js";
export { RecoveryPhraseGenerator } from "./client-registration/domain/service/recovery-phrase-generator.js";
export { RecoveryVerifier } from "./client-registration/domain/service/recovery-verifier.js";

// --- Application Use Cases ---
export { EnrollClientUseCase } from "./client-registration/application/usecase/enroll-client.usecase.js";
export { RevokeClientUseCase } from "./client-registration/application/usecase/revoke-client.usecase.js";
export { RotateCommitmentUseCase } from "./client-registration/application/usecase/rotate-commitment.usecase.js";
export { RecoverViaPhraseUseCase } from "./client-registration/application/usecase/recover-via-phrase.usecase.js";
export { ReactivateViaExternalUseCase } from "./client-registration/application/usecase/reactivate-via-external.usecase.js";

// --- Shared Errors ---
export { EnrollmentError } from "./shared/errors.js";
export type { EnrollmentErrorCode } from "./shared/errors.js";
export { LifecycleError } from "./shared/errors.js";
export type { LifecycleErrorCode } from "./shared/errors.js";

// --- Factory ---
export {
  createEnrollmentService,
  type EnrollmentServiceDependencies,
} from "./create-enrollment-service.js";

// --- Reference Adapters ---
export { InMemoryClientRepository } from "./client-registration/infrastructure/adapter/outgoing/in-memory-client-repository.js";
export { StubCommitmentVerifier } from "./client-registration/infrastructure/adapter/outgoing/stub-commitment-verifier.js";
export type { StubCommitmentVerifierConfig } from "./client-registration/infrastructure/adapter/outgoing/stub-commitment-verifier.js";
export { StubProofOfPossessionVerifier } from "./client-registration/infrastructure/adapter/outgoing/stub-proof-of-possession-verifier.js";
export { CryptoRandomIdGenerator } from "./client-registration/infrastructure/adapter/outgoing/crypto-random-id-generator.js";
export { ConsoleAuditLogger } from "./client-registration/infrastructure/adapter/outgoing/console-audit-logger.js";
export { NoopEventPublisher } from "./client-registration/infrastructure/adapter/outgoing/noop-event-publisher.js";
export { StubTokenInvalidator } from "./client-registration/infrastructure/adapter/outgoing/stub-token-invalidator.js";
export { StubChallengeInvalidator } from "./client-registration/infrastructure/adapter/outgoing/stub-challenge-invalidator.js";
export { StubRotationProofVerifier } from "./client-registration/infrastructure/adapter/outgoing/stub-rotation-proof-verifier.js";
export { StubAdminAuthenticator } from "./client-registration/infrastructure/adapter/outgoing/stub-admin-authenticator.js";
export { InMemoryRecoveryHashStore } from "./client-registration/infrastructure/adapter/outgoing/in-memory-recovery-hash-store.js";
export { StubArgon2Hasher } from "./client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";
export { StubBip39WordlistProvider } from "./client-registration/infrastructure/adapter/outgoing/stub-bip39-wordlist-provider.js";
export { CryptoSecureRandomProvider } from "./client-registration/infrastructure/adapter/outgoing/crypto-secure-random-provider.js";

// --- Lifecycle Factory ---
export {
  createLifecycleService,
  type LifecycleServiceDependencies,
  type LifecycleService,
} from "./create-lifecycle-service.js";

// --- Recovery Factory ---
export {
  createRecoveryService,
  type RecoveryServiceDependencies,
  type RecoveryService,
} from "./create-recovery-service.js";

// ===== Authentication Challenge Bounded Context =====

// --- Domain Models ---
export { Nonce } from "./authentication-challenge/domain/model/nonce.js";
export { ChallengeId } from "./authentication-challenge/domain/model/challenge-id.js";
export { ChannelBinding } from "./authentication-challenge/domain/model/channel-binding.js";
export { ChallengeExpiry } from "./authentication-challenge/domain/model/challenge-expiry.js";
export { ProtocolVersion } from "./authentication-challenge/domain/model/protocol-version.js";
export { FirstFactorType } from "./authentication-challenge/domain/model/first-factor-type.js";
export { Challenge } from "./authentication-challenge/domain/model/challenge.js";
export type { ChallengeStatus } from "./authentication-challenge/domain/model/challenge.js";

// --- Domain Events ---
export { ChallengeIssued } from "./authentication-challenge/domain/event/challenge-issued.js";
export { ChallengeInvalidated } from "./authentication-challenge/domain/event/challenge-invalidated.js";

// --- Domain Ports (Incoming) ---
export type { RequestChallenge } from "./authentication-challenge/domain/port/incoming/request-challenge.js";
export type { CheckChallenge } from "./authentication-challenge/domain/port/incoming/check-challenge.js";

// --- Domain Ports (Outgoing) ---
export type { ChallengeRepository } from "./authentication-challenge/domain/port/outgoing/challenge-repository.js";
export type { NonceGenerator } from "./authentication-challenge/domain/port/outgoing/nonce-generator.js";
export type { CredentialVerifier, CredentialVerificationResult } from "./authentication-challenge/domain/port/outgoing/credential-verifier.js";
export type { ClientStatusChecker, LockoutInfo } from "./authentication-challenge/domain/port/outgoing/client-status-checker.js";
export type { Clock } from "./authentication-challenge/domain/port/outgoing/clock.js";

// --- Application DTOs ---
export type { RequestChallengeRequest } from "./authentication-challenge/application/dto/request-challenge.request.js";
export type { RequestChallengeResponse, ChallengeErrorCode } from "./authentication-challenge/application/dto/request-challenge.response.js";
export type { CheckChallengeRequest } from "./authentication-challenge/application/dto/check-challenge.request.js";
export type { CheckChallengeResponse } from "./authentication-challenge/application/dto/check-challenge.response.js";

// --- Domain Service ---
export { ChallengeIssuancePolicy } from "./authentication-challenge/domain/service/challenge-issuance-policy.js";
export { ChallengeIssuanceError } from "./authentication-challenge/domain/service/challenge-issuance-policy.js";

// --- Application Use Cases ---
export { RequestChallengeUseCase } from "./authentication-challenge/application/usecase/request-challenge.usecase.js";
export { CheckChallengeUseCase } from "./authentication-challenge/application/usecase/check-challenge.usecase.js";

// --- Factory ---
export { createChallengeService, type ChallengeServiceDependencies, type ChallengeService } from "./create-challenge-service.js";

// --- Reference Adapters ---
export { CryptoNonceGenerator } from "./authentication-challenge/infrastructure/adapter/outgoing/crypto-nonce-generator.js";
export { InMemoryChallengeRepository } from "./authentication-challenge/infrastructure/adapter/outgoing/in-memory-challenge-repository.js";
export { StubCredentialVerifier } from "./authentication-challenge/infrastructure/adapter/outgoing/stub-credential-verifier.js";
export { StubClientStatusChecker } from "./authentication-challenge/infrastructure/adapter/outgoing/stub-client-status-checker.js";
export { MonotonicClock } from "./authentication-challenge/infrastructure/adapter/outgoing/monotonic-clock.js";
export { NoopRateLimiter } from "./authentication-challenge/infrastructure/adapter/outgoing/noop-rate-limiter.js";

// ===== Zero-Knowledge Verification Bounded Context =====

// --- Domain Models ---
export { Proof, PROOF_BYTE_LENGTH } from "./zk-verification/domain/model/proof.js";
export { GroupElement } from "./zk-verification/domain/model/group-element.js";
export { ScalarValue } from "./zk-verification/domain/model/scalar-value.js";
export { DomainSeparationTag } from "./zk-verification/domain/model/domain-separation-tag.js";
export { Transcript } from "./zk-verification/domain/model/transcript.js";
export type { TranscriptFields } from "./zk-verification/domain/model/transcript.js";

// --- Domain Events ---
export { ProofVerified } from "./zk-verification/domain/event/proof-verified.js";

// --- Domain Ports (Incoming) ---
export type {
  VerifyProof,
  VerifyProofRequest,
  VerifyProofResponse,
  VerificationErrorCode,
} from "./zk-verification/domain/port/incoming/verify-proof.js";

// --- Domain Ports (Outgoing) ---
export type { ElementValidator } from "./zk-verification/domain/port/outgoing/element-validator.js";
export type { CommitmentLookup, CommitmentInfo } from "./zk-verification/domain/port/outgoing/commitment-lookup.js";
export type { ChallengeConsumer, ChallengeInfo } from "./zk-verification/domain/port/outgoing/challenge-consumer.js";
export type { TranscriptHasher } from "./zk-verification/domain/port/outgoing/transcript-hasher.js";
export type { ProofEquationVerifier } from "./zk-verification/domain/port/outgoing/proof-equation-verifier.js";
export type { FailedAttemptTracker } from "./zk-verification/domain/port/outgoing/failed-attempt-tracker.js";
export type { BatchProofVerifier } from "./zk-verification/domain/port/outgoing/batch-proof-verifier.js";
export type {
  AuditLogger as VerificationAuditLogger,
  AuditEntry as VerificationAuditEntry,
} from "./zk-verification/domain/port/outgoing/audit-logger.js";
export type {
  EventPublisher as VerificationEventPublisher,
  DomainEvent as VerificationDomainEvent,
} from "./zk-verification/domain/port/outgoing/event-publisher.js";
export type { Clock as VerificationClock } from "./zk-verification/domain/port/outgoing/clock.js";
export type { RateLimiter as VerificationRateLimiter } from "./zk-verification/domain/port/outgoing/rate-limiter.js";

// --- Application DTOs ---
export type { VerifyProofRequest as VerifyProofRequestDto } from "./zk-verification/application/dto/verify-proof.request.js";
export type { VerifyProofResponse as VerifyProofResponseDto } from "./zk-verification/application/dto/verify-proof.response.js";

// --- Domain Services ---
export { ProofVerificationPolicy } from "./zk-verification/domain/service/proof-verification-policy.js";
export { ProofVerificationError } from "./zk-verification/domain/service/proof-verification-policy.js";
export type { ProofVerificationErrorCode } from "./zk-verification/domain/service/proof-verification-policy.js";
export { BatchVerificationService } from "./zk-verification/domain/service/batch-verification-service.js";
export { InputHardeningPolicy, InputHardeningError } from "./zk-verification/domain/service/input-hardening-policy.js";
export type { InputHardeningErrorCode } from "./zk-verification/domain/service/input-hardening-policy.js";

// --- Application Use Case ---
export { VerifyProofUseCase } from "./zk-verification/application/usecase/verify-proof.usecase.js";

// --- Factory ---
export {
  createVerificationService,
  type VerificationServiceDependencies,
  type VerificationService,
} from "./create-verification-service.js";

// --- Reference Adapters ---
export { StubElementValidator } from "./zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
export type { StubElementValidatorConfig } from "./zk-verification/infrastructure/adapter/outgoing/stub-element-validator.js";
export { StubCommitmentLookup } from "./zk-verification/infrastructure/adapter/outgoing/stub-commitment-lookup.js";
export { StubChallengeConsumer } from "./zk-verification/infrastructure/adapter/outgoing/stub-challenge-consumer.js";
export { StubProofEquationVerifier } from "./zk-verification/infrastructure/adapter/outgoing/stub-proof-equation-verifier.js";
export { StubTranscriptHasher } from "./zk-verification/infrastructure/adapter/outgoing/stub-transcript-hasher.js";
export { StubFailedAttemptTracker } from "./zk-verification/infrastructure/adapter/outgoing/stub-failed-attempt-tracker.js";

// ===== API Access Control Bounded Context =====

// --- Domain Models ---
export { TokenId } from "./api-access-control/domain/model/token-id.js";
export { Audience } from "./api-access-control/domain/model/audience.js";
export {
  AuthenticationLevel,
  STANDARD_TTL_MS,
  ELEVATED_TTL_MS,
  ttlForLevel,
} from "./api-access-control/domain/model/authentication-level.js";
export { TokenClaims } from "./api-access-control/domain/model/token-claims.js";
export type { TokenClaimsInput } from "./api-access-control/domain/model/token-claims.js";
export { AccessToken } from "./api-access-control/domain/model/access-token.js";

// --- Domain Events ---
export { TokenIssued } from "./api-access-control/domain/event/token-issued.js";

// --- Domain Ports (Incoming) ---
export type {
  IssueToken,
  IssueTokenRequest,
  IssueTokenResponse,
} from "./api-access-control/domain/port/incoming/issue-token.js";
export type {
  ValidateToken,
  ValidateTokenRequest,
  ValidateTokenResponse,
} from "./api-access-control/domain/port/incoming/validate-token.js";

// --- Domain Ports (Outgoing) ---
export type { TokenSigner } from "./api-access-control/domain/port/outgoing/token-signer.js";
export type { TokenVerifier } from "./api-access-control/domain/port/outgoing/token-verifier.js";
export type {
  ClientStatusChecker as AccessControlClientStatusChecker,
} from "./api-access-control/domain/port/outgoing/client-status-checker.js";
export type { AuthorizationChecker } from "./api-access-control/domain/port/outgoing/authorization-checker.js";
export type {
  AuditLogger as AccessControlAuditLogger,
  AuditEntry as AccessControlAuditEntry,
} from "./api-access-control/domain/port/outgoing/audit-logger.js";
export type {
  EventPublisher as AccessControlEventPublisher,
  DomainEvent as AccessControlDomainEvent,
} from "./api-access-control/domain/port/outgoing/event-publisher.js";
export type { Clock as AccessControlClock } from "./api-access-control/domain/port/outgoing/clock.js";
export type { IdGenerator as AccessControlIdGenerator } from "./api-access-control/domain/port/outgoing/id-generator.js";

// --- Application DTOs ---
export type { IssueTokenRequest as IssueTokenRequestDto } from "./api-access-control/application/dto/issue-token.request.js";
export type { IssueTokenResponse as IssueTokenResponseDto } from "./api-access-control/application/dto/issue-token.response.js";
export type { ValidateTokenRequest as ValidateTokenRequestDto } from "./api-access-control/application/dto/validate-token.request.js";
export type { ValidateTokenResponse as ValidateTokenResponseDto } from "./api-access-control/application/dto/validate-token.response.js";

// --- Domain Services ---
export { TokenIssuancePolicy, IssuancePolicyError } from "./api-access-control/domain/service/token-issuance-policy.js";
export type { IssuancePolicyErrorCode, IssuancePreconditions } from "./api-access-control/domain/service/token-issuance-policy.js";
export { TokenValidationChain, ValidationError } from "./api-access-control/domain/service/token-validation-chain.js";
export type { ValidationErrorCode, ValidationInput } from "./api-access-control/domain/service/token-validation-chain.js";

// --- Application Use Cases ---
export { IssueTokenUseCase } from "./api-access-control/application/usecase/issue-token.usecase.js";
export { ValidateTokenUseCase } from "./api-access-control/application/usecase/validate-token.usecase.js";

// --- Factory ---
export {
  createAccessControlService,
  type AccessControlServiceDependencies,
  type AccessControlService,
} from "./create-access-control-service.js";

// --- Reference Adapters ---
export { StubTokenSigner } from "./api-access-control/infrastructure/adapter/outgoing/stub-token-signer.js";
export { StubTokenVerifier } from "./api-access-control/infrastructure/adapter/outgoing/stub-token-verifier.js";
export { StubClientStatusChecker as AccessControlStubClientStatusChecker } from "./api-access-control/infrastructure/adapter/outgoing/stub-client-status-checker.js";
export { StubAuthorizationChecker } from "./api-access-control/infrastructure/adapter/outgoing/stub-authorization-checker.js";

// ===== Security Monitoring Bounded Context =====

// --- Domain Models ---
export { FailedAttemptCounter } from "./security-monitoring/domain/model/failed-attempt-counter.js";
export { LockoutConfig } from "./security-monitoring/domain/model/lockout-config.js";
export { LockoutStatus } from "./security-monitoring/domain/model/lockout-status.js";
export { AuditEntry } from "./security-monitoring/domain/model/audit-entry.js";
export type { AuditEntryInput } from "./security-monitoring/domain/model/audit-entry.js";
export { AuditEventType, KNOWN_AUDIT_EVENT_TYPES } from "./security-monitoring/domain/model/audit-event-type.js";
export type { KnownAuditEventType } from "./security-monitoring/domain/model/audit-event-type.js";
export { RetentionPolicy } from "./security-monitoring/domain/model/retention-policy.js";
export { AnomalyAlert } from "./security-monitoring/domain/model/anomaly-alert.js";
export type { AnomalyAlertInput } from "./security-monitoring/domain/model/anomaly-alert.js";
export type { AnomalyType } from "./security-monitoring/domain/model/anomaly-type.js";

// --- Domain Events ---
export { ClientLockedOut } from "./security-monitoring/domain/event/client-locked-out.js";
export { AnomalyDetected } from "./security-monitoring/domain/event/anomaly-detected.js";

// --- Domain Ports (Incoming) ---
export type {
  RecordFailedAttempt,
  RecordFailedAttemptRequest,
  RecordFailedAttemptResponse,
} from "./security-monitoring/domain/port/incoming/record-failed-attempt.js";
export type {
  RecordSuccessfulAuth,
  RecordSuccessfulAuthRequest,
  RecordSuccessfulAuthResponse,
} from "./security-monitoring/domain/port/incoming/record-successful-auth.js";
export type {
  CheckLockoutStatus,
  CheckLockoutStatusRequest,
  CheckLockoutStatusResponse,
} from "./security-monitoring/domain/port/incoming/check-lockout-status.js";
export type {
  RecordAuditEvent,
  RecordAuditEventRequest,
  RecordAuditEventResponse,
} from "./security-monitoring/domain/port/incoming/record-audit-event.js";
export type {
  DetectAnomalies,
  DetectAnomaliesRequest,
  DetectAnomaliesResponse,
} from "./security-monitoring/domain/port/incoming/detect-anomalies.js";

// --- Domain Ports (Outgoing) ---
export type { AttemptCounterStore } from "./security-monitoring/domain/port/outgoing/attempt-counter-store.js";
export type { AuditLogStore } from "./security-monitoring/domain/port/outgoing/audit-log-store.js";
export type { AnomalyBaselineStore, ClientBaseline } from "./security-monitoring/domain/port/outgoing/anomaly-baseline-store.js";
export type { AlertDispatcher } from "./security-monitoring/domain/port/outgoing/alert-dispatcher.js";
export type {
  EventPublisher as MonitoringEventPublisher,
  DomainEvent as MonitoringDomainEvent,
} from "./security-monitoring/domain/port/outgoing/event-publisher.js";
export type { Clock as MonitoringClock } from "./security-monitoring/domain/port/outgoing/clock.js";
export type { IdGenerator as MonitoringIdGenerator } from "./security-monitoring/domain/port/outgoing/id-generator.js";

// --- Domain Services ---
export { LockoutPolicy } from "./security-monitoring/domain/service/lockout-policy.js";
export { AnomalyDetectionEngine } from "./security-monitoring/domain/service/anomaly-detection-engine.js";
export type { FailureRecord, LockoutRecord, AnomalyResult } from "./security-monitoring/domain/service/anomaly-detection-engine.js";

// --- Application Use Cases ---
export { RecordFailedAttemptUseCase } from "./security-monitoring/application/usecase/record-failed-attempt.usecase.js";
export { RecordSuccessfulAuthUseCase } from "./security-monitoring/application/usecase/record-successful-auth.usecase.js";
export { CheckLockoutStatusUseCase } from "./security-monitoring/application/usecase/check-lockout-status.usecase.js";
export { RecordAuditEventUseCase } from "./security-monitoring/application/usecase/record-audit-event.usecase.js";
export { DetectAnomaliesUseCase } from "./security-monitoring/application/usecase/detect-anomalies.usecase.js";

// --- Factory ---
export {
  createMonitoringService,
  type MonitoringServiceDependencies,
  type MonitoringService,
} from "./create-monitoring-service.js";

// --- Reference Adapters ---
export { InMemoryAttemptCounterStore } from "./security-monitoring/infrastructure/adapter/outgoing/in-memory-attempt-counter-store.js";
export { InMemoryAuditLogStore } from "./security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
export { InMemoryAnomalyBaselineStore } from "./security-monitoring/infrastructure/adapter/outgoing/in-memory-anomaly-baseline-store.js";
export { StubAlertDispatcher } from "./security-monitoring/infrastructure/adapter/outgoing/stub-alert-dispatcher.js";
export { NoopEventPublisher as MonitoringNoopEventPublisher } from "./security-monitoring/infrastructure/adapter/outgoing/noop-event-publisher.js";

// ===== Configuration & Bootstrap =====
export { detectEnvironment, loadConfigFromEnv } from "./config/environment.js";
export type { Environment, TwoFApiConfig, DatabaseConfig, RedisConfig, CryptoConfig } from "./config/environment.js";
export { createDevelopmentServices } from "./config/development-services.js";
export type { AllServices } from "./config/development-services.js";
export { bootstrap } from "./config/bootstrap.js";

// ===== PostgreSQL Adapters =====
export { PgClientRepository } from "./client-registration/infrastructure/adapter/outgoing/pg-client-repository.js";
export { PgRecoveryHashStore } from "./client-registration/infrastructure/adapter/outgoing/pg-recovery-hash-store.js";
export { PgChallengeRepository } from "./authentication-challenge/infrastructure/adapter/outgoing/pg-challenge-repository.js";
export { PgAttemptCounterStore } from "./security-monitoring/infrastructure/adapter/outgoing/pg-attempt-counter-store.js";
export { PgAuditLogStore } from "./security-monitoring/infrastructure/adapter/outgoing/pg-audit-log-store.js";
export { PgIpBindingStore } from "./security-monitoring/infrastructure/adapter/outgoing/pg-ip-binding-store.js";
export { PgAnomalyBaselineStore } from "./security-monitoring/infrastructure/adapter/outgoing/pg-anomaly-baseline-store.js";

// ===== Redis Adapters =====
export { RedisChallengeRepository } from "./authentication-challenge/infrastructure/adapter/outgoing/redis-challenge-repository.js";
export { RedisVerificationReceiptStore } from "./api-access-control/infrastructure/adapter/outgoing/redis-verification-receipt-store.js";
export { RedisAttemptCounterStore } from "./security-monitoring/infrastructure/adapter/outgoing/redis-attempt-counter-store.js";
export { RedisGlobalRateLimiter } from "./shared/redis-global-rate-limiter.js";
export { RedisIpRateLimiter } from "./shared/redis-ip-rate-limiter.js";
export { RedisRateLimiter } from "./shared/infrastructure/adapter/outgoing/redis-rate-limiter.js";

// ===== Crypto Adapters =====
export { EddsaTokenSigner } from "./api-access-control/infrastructure/adapter/outgoing/eddsa-token-signer.js";
export { EddsaTokenVerifier } from "./api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js";
export { RealArgon2Hasher } from "./client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js";
export { JwtAdminAuthenticator } from "./client-registration/infrastructure/adapter/outgoing/jwt-admin-authenticator.js";

// ===== Shared Rate Limiters =====
export { InMemoryGlobalRateLimiter } from "./shared/global-rate-limiter.js";
export type { GlobalRateLimiter, RateLimitResult } from "./shared/global-rate-limiter.js";
export { InMemoryIpRateLimiter } from "./api-gateway/middleware/ip-rate-limiter.js";
export type { IpRateLimiter, IpRateLimiterResult } from "./api-gateway/middleware/ip-rate-limiter.js";
export { InMemoryVerificationReceiptStore } from "./api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";
export type { VerificationReceiptStore } from "./api-access-control/domain/port/outgoing/verification-receipt-store.js";
export type { IpBindingStore } from "./security-monitoring/domain/port/outgoing/ip-binding-store.js";
export { InMemoryIpBindingStore } from "./security-monitoring/infrastructure/adapter/outgoing/in-memory-ip-binding-store.js";
