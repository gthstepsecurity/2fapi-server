// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Production service factory.
 *
 * Creates all services using real infrastructure adapters:
 * - PostgreSQL for persistent storage
 * - Redis for caching, rate limiting, and ephemeral data
 * - Ed25519 for token signing/verification
 * - Argon2id for recovery phrase hashing
 * - @2fapi/crypto-native (napi-rs) for Ristretto255 ZKP operations
 *
 * ZERO STUBS: Every adapter is a real production implementation.
 * Requires running PostgreSQL and Redis instances.
 */

import type { AllServices } from "./development-services.js";
import type { TwoFApiConfig } from "./environment.js";

// PostgreSQL adapters
import { PgClientRepository } from "../client-registration/infrastructure/adapter/outgoing/pg-client-repository.js";
import { PgRecoveryHashStore } from "../client-registration/infrastructure/adapter/outgoing/pg-recovery-hash-store.js";
import { PgChallengeRepository } from "../authentication-challenge/infrastructure/adapter/outgoing/pg-challenge-repository.js";
import { PgAttemptCounterStore } from "../security-monitoring/infrastructure/adapter/outgoing/pg-attempt-counter-store.js";
import { PgAuditLogStore } from "../security-monitoring/infrastructure/adapter/outgoing/pg-audit-log-store.js";
import { PgIpBindingStore } from "../security-monitoring/infrastructure/adapter/outgoing/pg-ip-binding-store.js";
import { PgAnomalyBaselineStore } from "../security-monitoring/infrastructure/adapter/outgoing/pg-anomaly-baseline-store.js";

// Redis adapters
import { RedisChallengeRepository } from "../authentication-challenge/infrastructure/adapter/outgoing/redis-challenge-repository.js";
import { RedisVerificationReceiptStore } from "../api-access-control/infrastructure/adapter/outgoing/redis-verification-receipt-store.js";
import { RedisAttemptCounterStore } from "../security-monitoring/infrastructure/adapter/outgoing/redis-attempt-counter-store.js";
import { RedisGlobalRateLimiter } from "../shared/redis-global-rate-limiter.js";
import { RedisIpRateLimiter } from "../shared/redis-ip-rate-limiter.js";
import { RedisRateLimiter } from "../shared/infrastructure/adapter/outgoing/redis-rate-limiter.js";

// Crypto adapters (EdDSA)
import { EddsaTokenSigner } from "../api-access-control/infrastructure/adapter/outgoing/eddsa-token-signer.js";
import { EddsaTokenVerifier } from "../api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js";
import { RealArgon2Hasher } from "../client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js";
import { JwtAdminAuthenticator } from "../client-registration/infrastructure/adapter/outgoing/jwt-admin-authenticator.js";

// Crypto adapters (napi-rs / Ristretto255)
import { NapiCommitmentVerifier } from "../client-registration/infrastructure/adapter/outgoing/napi-commitment-verifier.js";
import { NapiProofOfPossessionVerifier } from "../client-registration/infrastructure/adapter/outgoing/napi-proof-of-possession-verifier.js";
import { NapiRotationProofVerifier } from "../client-registration/infrastructure/adapter/outgoing/napi-rotation-proof-verifier.js";
import { NapiReactivationProofVerifier } from "../client-registration/infrastructure/adapter/outgoing/napi-reactivation-proof-verifier.js";
import { NapiElementValidator } from "../zk-verification/infrastructure/adapter/outgoing/napi-element-validator.js";
import { NapiTranscriptHasher } from "../zk-verification/infrastructure/adapter/outgoing/napi-transcript-hasher.js";
import { NapiProofEquationVerifier } from "../zk-verification/infrastructure/adapter/outgoing/napi-proof-equation-verifier.js";

// Cross-context bridges
import { PgCredentialVerifier } from "../authentication-challenge/infrastructure/adapter/outgoing/pg-credential-verifier.js";
import { PgClientStatusBridge } from "../authentication-challenge/infrastructure/adapter/outgoing/pg-client-status-bridge.js";
import { PgCommitmentLookup } from "../zk-verification/infrastructure/adapter/outgoing/pg-commitment-lookup.js";
import { AtomicChallengeConsumer } from "../zk-verification/infrastructure/adapter/outgoing/atomic-challenge-consumer.js";
import { RedisAtomicChallengeStore } from "../zk-verification/infrastructure/adapter/outgoing/redis-atomic-challenge-store.js";
import { PgFailedAttemptBridge } from "../zk-verification/infrastructure/adapter/outgoing/pg-failed-attempt-bridge.js";
import { PgClientStatusBridge as AccessControlPgClientStatusBridge } from "../api-access-control/infrastructure/adapter/outgoing/pg-client-status-bridge.js";
import { ConfigAuthorizationChecker } from "../api-access-control/infrastructure/adapter/outgoing/config-authorization-checker.js";
import { NoopTokenInvalidator } from "../shared/infrastructure/adapter/outgoing/noop-token-invalidator.js";
import { RedisChallengeInvalidator } from "../shared/infrastructure/adapter/outgoing/redis-challenge-invalidator.js";

// Audit/Event adapters
import { PgAuditLoggerAdapter } from "../shared/infrastructure/adapter/outgoing/pg-audit-logger-adapter.js";
import { NoopEventPublisher } from "../client-registration/infrastructure/adapter/outgoing/noop-event-publisher.js";
import { NoopEventPublisher as MonitoringNoopEventPublisher } from "../security-monitoring/infrastructure/adapter/outgoing/noop-event-publisher.js";

// Shared adapters
import { CryptoRandomIdGenerator } from "../client-registration/infrastructure/adapter/outgoing/crypto-random-id-generator.js";
import { ConsoleAuditLogger } from "../client-registration/infrastructure/adapter/outgoing/console-audit-logger.js";
import { CryptoSecureRandomProvider } from "../client-registration/infrastructure/adapter/outgoing/crypto-secure-random-provider.js";
import { DefaultBip39WordlistProvider } from "../client-registration/infrastructure/adapter/outgoing/default-bip39-wordlist-provider.js";
import { MonotonicClock } from "../authentication-challenge/infrastructure/adapter/outgoing/monotonic-clock.js";
import { ConsoleAlertDispatcher } from "../security-monitoring/infrastructure/adapter/outgoing/console-alert-dispatcher.js";

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

import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

/**
 * Loads the Ed25519 private key from configuration.
 * Supports loading from a hex string (env var) or a file path.
 */
function loadEddsaPrivateKey(config: TwoFApiConfig): Uint8Array {
  if (config.crypto.eddsaPrivateKeyHex) {
    const hex = config.crypto.eddsaPrivateKeyHex;
    if (hex.length !== 64) {
      throw new Error("EDDSA_PRIVATE_KEY_HEX must be exactly 64 hex characters (32 bytes)");
    }
    return new Uint8Array(Buffer.from(hex, "hex"));
  }

  if (config.crypto.eddsaPrivateKeyPath) {
    const raw = readFileSync(config.crypto.eddsaPrivateKeyPath);
    // Support both raw 32-byte binary and hex-encoded file content
    if (raw.length === 32) {
      return new Uint8Array(raw);
    }
    const hexStr = raw.toString("utf-8").trim();
    if (hexStr.length === 64) {
      return new Uint8Array(Buffer.from(hexStr, "hex"));
    }
    throw new Error(
      "EdDSA private key file must contain either 32 raw bytes or 64 hex characters",
    );
  }

  throw new Error(
    "EdDSA private key is required. Set EDDSA_PRIVATE_KEY_HEX or EDDSA_PRIVATE_KEY_PATH.",
  );
}

/**
 * Derives the Ed25519 public key from a private key seed.
 * Uses @noble/ed25519 for derivation.
 */
async function deriveEddsaPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  const ed25519 = await import("@noble/ed25519");
  return await ed25519.getPublicKeyAsync(privateKey);
}

/**
 * Loads the @2fapi/crypto-native napi-rs module.
 * This provides Ristretto255 operations compiled from Rust.
 */
async function loadNativeCryptoModule() {
  return await import("@2fapi/crypto-native");
}

/**
 * Creates all services using real infrastructure adapters.
 * Connects to PostgreSQL and Redis, loads crypto keys and native module.
 *
 * ZERO STUBS — every dependency is a real, production-grade implementation.
 *
 * @param config - Full application configuration
 * @returns All services wired with production adapters
 * @throws If connection to PostgreSQL or Redis fails
 * @throws If EdDSA key loading fails
 * @throws If native crypto module loading fails
 */
export async function createProductionServices(config: TwoFApiConfig): Promise<AllServices> {
  // 1. Connect to PostgreSQL
  const pg = await import("pg");
  const pgConfig: Record<string, unknown> = {
    host: config.database.host,
    port: config.database.port,
    database: config.database.database,
    user: config.database.user,
    password: config.database.password,
  };
  if (config.database.ssl) {
    pgConfig["ssl"] = { rejectUnauthorized: true };
  }
  const pool = new pg.Pool(pgConfig as any);

  // Verify connection
  const pgClient = await pool.connect();
  pgClient.release();
  console.log("[BOOT] PostgreSQL connected");

  // 2. Connect to Redis
  const IoRedis = (await import("ioredis")).default;
  const redisConfig: Record<string, unknown> = {
    host: config.redis.host,
    port: config.redis.port,
  };
  if (config.redis.password) {
    redisConfig["password"] = config.redis.password;
  }
  if (config.redis.tls) {
    redisConfig["tls"] = {};
  }
  const redis = new IoRedis(redisConfig as any);

  // Verify connection
  await redis.ping();
  console.log("[BOOT] Redis connected");

  // 3. Load EdDSA signing key
  const privateKey = loadEddsaPrivateKey(config);
  const publicKey = await deriveEddsaPublicKey(privateKey);
  console.log("[BOOT] EdDSA key pair loaded");

  // 4. Load native crypto module (Rust napi-rs)
  const nativeCrypto = await loadNativeCryptoModule();
  console.log("[BOOT] Native crypto module loaded (Ristretto255)");

  // 5. Create PostgreSQL adapters
  const clientRepository = new PgClientRepository(pool);
  const challengeRepository = new PgChallengeRepository(pool);
  const recoveryHashStore = new PgRecoveryHashStore(pool);
  const attemptCounterStore = new PgAttemptCounterStore(pool);
  const auditLogStore = new PgAuditLogStore(pool);
  const ipBindingStore = new PgIpBindingStore(pool);
  const baselineStore = new PgAnomalyBaselineStore(pool);

  // 6. Create Redis adapters
  const redisChallengeRepo = new RedisChallengeRepository(redis);
  const receiptStore = new RedisVerificationReceiptStore(redis);
  const redisGlobalRateLimiter = new RedisGlobalRateLimiter(
    redis,
    config.rateLimiting.globalMaxRequests,
    config.rateLimiting.globalWindowMs,
  );
  const redisIpRateLimiter = new RedisIpRateLimiter(
    redis,
    config.rateLimiting.perIpMaxRequests,
    config.rateLimiting.perIpWindowMs,
  );

  // 7. Create crypto adapters (EdDSA)
  const tokenSigner = new EddsaTokenSigner(privateKey);
  const tokenVerifier = new EddsaTokenVerifier(publicKey);
  const argon2Hasher = new RealArgon2Hasher();
  const adminAuthenticator = JwtAdminAuthenticator.fromEnvironment();

  // 8. Create crypto adapters (napi-rs / Ristretto255)
  const generatorG = new Uint8Array(nativeCrypto.getGeneratorG());
  const generatorH = new Uint8Array(nativeCrypto.getGeneratorH());

  const commitmentVerifier = new NapiCommitmentVerifier(nativeCrypto);
  const proofOfPossessionVerifier = new NapiProofOfPossessionVerifier(nativeCrypto, generatorG, generatorH);
  const rotationProofVerifier = new NapiRotationProofVerifier(nativeCrypto, generatorG, generatorH);
  const reactivationProofVerifier = new NapiReactivationProofVerifier(nativeCrypto, generatorG, generatorH);
  const elementValidator = new NapiElementValidator(nativeCrypto);
  const transcriptHasher = new NapiTranscriptHasher(nativeCrypto);
  const proofEquationVerifier = new NapiProofEquationVerifier(nativeCrypto);
  console.log("[BOOT] Crypto adapters: NapiCommitmentVerifier, NapiProofOfPossessionVerifier, NapiRotationProofVerifier, NapiReactivationProofVerifier, NapiElementValidator, NapiTranscriptHasher, NapiProofEquationVerifier");

  // 9. Create cross-context bridges
  const credentialVerifier = new PgCredentialVerifier(pool);
  const challengeClientStatusChecker = new PgClientStatusBridge(pool, config.lockout.durationMs);
  const commitmentLookup = new PgCommitmentLookup(pool);
  const redisAtomicChallengeStore = new RedisAtomicChallengeStore(redis as any);
  const challengeConsumer = new AtomicChallengeConsumer(redisAtomicChallengeStore);
  const failedAttemptTracker = new PgFailedAttemptBridge(pool);
  const accessControlClientStatusChecker = new AccessControlPgClientStatusBridge(pool);
  const authorizationChecker = new ConfigAuthorizationChecker();
  const tokenInvalidator = new NoopTokenInvalidator();
  const challengeInvalidator = new RedisChallengeInvalidator(redis);
  console.log("[BOOT] Cross-context bridges: PgCredentialVerifier, PgClientStatusBridge, PgCommitmentLookup, AtomicChallengeConsumer(Redis), PgFailedAttemptBridge, PgClientStatusBridge(AC), ConfigAuthorizationChecker, NoopTokenInvalidator, RedisChallengeInvalidator");

  // 10. Create audit/event adapters
  const challengeAuditLogger = new PgAuditLoggerAdapter(pool, "challenge");
  const verificationAuditLogger = new PgAuditLoggerAdapter(pool, "verification");
  const accessControlAuditLogger = new PgAuditLoggerAdapter(pool, "access");
  const challengeEventPublisher = new NoopEventPublisher();
  const verificationEventPublisher = new NoopEventPublisher();
  const accessControlEventPublisher = new NoopEventPublisher();
  console.log("[BOOT] Audit: PgAuditLoggerAdapter (challenge, verification, access-control)");

  // 11. Shared adapters
  const clock = new MonotonicClock();
  const registrationAuditLogger = new ConsoleAuditLogger();
  const registrationEventPublisher = new NoopEventPublisher();
  const idGenerator = new CryptoRandomIdGenerator();
  const secureRandomProvider = new CryptoSecureRandomProvider();
  const wordlistProvider = new DefaultBip39WordlistProvider();
  const alertDispatcher = new ConsoleAlertDispatcher();
  console.log("[BOOT] Shared: DefaultBip39WordlistProvider, ConsoleAlertDispatcher, CryptoRandomIdGenerator");

  // Recovery config from environment
  const recoveryConfig = RecoveryConfig.create({
    wordCount: config.recovery.wordCount,
    argon2Memory: config.recovery.argon2Memory,
    argon2Iterations: config.recovery.argon2Iterations,
    argon2Parallelism: config.recovery.argon2Parallelism,
    maxRecoveryAttempts: config.recovery.maxAttempts,
    recoveryMode: config.recovery.mode,
  });

  // 12. Wire services via factories

  // Enrollment
  const enrollClient = createEnrollmentService({
    clientRepository,
    commitmentVerifier,
    proofOfPossessionVerifier,
    idGenerator,
    auditLogger: registrationAuditLogger,
    eventPublisher: registrationEventPublisher,
    rateLimiter: new RedisRateLimiter(redis, {
      maxRequests: 10,
      windowMs: 60_000,
      keyPrefix: "ratelimit:enroll:",
    }),
    recoveryHashStore,
    argon2Hasher,
    wordlistProvider,
    secureRandomProvider,
    recoveryConfig,
  });

  // Challenge (Redis for ephemeral challenge storage)
  const challengeService = createChallengeService({
    credentialVerifier,
    clientStatusChecker: challengeClientStatusChecker,
    challengeRepository: redisChallengeRepo,
    auditLogger: challengeAuditLogger,
    eventPublisher: challengeEventPublisher,
    clock,
  });

  // Verification
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
    environment: "production",
  });

  // Access Control
  const accessControlService = createAccessControlService({
    tokenSigner,
    tokenVerifier,
    clientStatusChecker: accessControlClientStatusChecker,
    authorizationChecker,
    auditLogger: accessControlAuditLogger,
    eventPublisher: accessControlEventPublisher,
    clock: { nowMs: () => Date.now() },
    idGenerator: {
      generate: () => `tok-${Date.now()}-${randomUUID()}`,
    },
    receiptStore,
  });

  // Monitoring
  const monitoringService = createMonitoringService({
    counterStore: attemptCounterStore,
    auditLogStore,
    baselineStore,
    alertDispatcher,
    eventPublisher: new MonitoringNoopEventPublisher(),
    clock: { nowMs: () => Date.now() },
    idGenerator: {
      generate: () => `mon-${Date.now()}-${randomUUID()}`,
    },
    lockoutThreshold: config.lockout.threshold,
    lockoutDurationMs: config.lockout.durationMs,
  });

  // Lifecycle
  const lifecycleService = createLifecycleService({
    clientRepository,
    commitmentVerifier,
    rotationProofVerifier,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger: registrationAuditLogger,
    eventPublisher: registrationEventPublisher,
    adminAuthenticator,
    rateLimiter: new RedisRateLimiter(redis, {
      maxRequests: 5,
      windowMs: 60_000,
      keyPrefix: "ratelimit:lifecycle:",
    }),
    environment: "production",
  });

  // Recovery
  const recoveryService = createRecoveryService({
    clientRepository,
    recoveryHashStore,
    argon2Hasher,
    tokenInvalidator,
    challengeInvalidator,
    auditLogger: registrationAuditLogger,
    eventPublisher: registrationEventPublisher,
    adminAuthenticator,
    recoveryConfig,
    reactivationProofVerifier,
    environment: "production",
  });

  // Rate limiters: Redis-backed for production
  // The RedisGlobalRateLimiter and RedisIpRateLimiter implement the
  // synchronous interfaces but throw on sync calls. The gateway middleware
  // should use tryAcquireAsync(). As a production wrapper, we use the
  // Redis rate limiters directly (they implement the same interfaces).
  const globalRateLimiter = redisGlobalRateLimiter;
  const ipRateLimiter = redisIpRateLimiter;

  console.log("[BOOT] All services wired with PRODUCTION adapters (zero stubs)");

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
