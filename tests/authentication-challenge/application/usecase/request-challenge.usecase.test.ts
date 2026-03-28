// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RequestChallengeUseCase } from "../../../../src/authentication-challenge/application/usecase/request-challenge.usecase.js";
import { ChallengeIssuancePolicy } from "../../../../src/authentication-challenge/domain/service/challenge-issuance-policy.js";
import { ProtocolVersion } from "../../../../src/authentication-challenge/domain/model/protocol-version.js";
import {
  createStubNonceGenerator,
  createStubCredentialVerifier,
  createStubClientStatusChecker,
  createStubRateLimiter,
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
  createStubIdGenerator,
  createInMemoryChallengeRepository,
  validChallengeRequest,
} from "../../../helpers/challenge-test-helpers.js";

const SUPPORTED_VERSIONS = [ProtocolVersion.fromString("1.0")];
const TTL_MS = 2 * 60 * 1000;

function createUseCase(overrides: {
  credentialVerifier?: ReturnType<typeof createStubCredentialVerifier>;
  clientStatusChecker?: ReturnType<typeof createStubClientStatusChecker>;
  rateLimiter?: ReturnType<typeof createStubRateLimiter>;
  repository?: ReturnType<typeof createInMemoryChallengeRepository>;
  auditLogger?: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher?: ReturnType<typeof createCapturingEventPublisher>;
  clock?: ReturnType<typeof createStubClock>;
  legacyMigrationActive?: boolean;
} = {}) {
  const credentialVerifier = overrides.credentialVerifier ?? createStubCredentialVerifier();
  const clientStatusChecker = overrides.clientStatusChecker ?? createStubClientStatusChecker();
  const rateLimiter = overrides.rateLimiter ?? createStubRateLimiter();
  const repository = overrides.repository ?? createInMemoryChallengeRepository();
  const auditLogger = overrides.auditLogger ?? createCapturingAuditLogger();
  const eventPublisher = overrides.eventPublisher ?? createCapturingEventPublisher();
  const clock = overrides.clock ?? createStubClock();
  const policy = new ChallengeIssuancePolicy(
    SUPPORTED_VERSIONS,
    overrides.legacyMigrationActive ?? false,
  );

  const useCase = new RequestChallengeUseCase(
    credentialVerifier,
    clientStatusChecker,
    rateLimiter,
    repository,
    createStubNonceGenerator(),
    createStubIdGenerator(),
    auditLogger,
    eventPublisher,
    clock,
    policy,
    TTL_MS,
  );

  return { useCase, repository, auditLogger, eventPublisher, clientStatusChecker };
}

describe("RequestChallengeUseCase", () => {
  it("should issue a challenge for a valid request", async () => {
    const { useCase } = createUseCase();

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.challengeId).toBeDefined();
      expect(result.nonce.length).toBeGreaterThanOrEqual(24);
      expect(result.channelBinding.length).toBe(32);
      expect(result.expiresAtMs).toBe(1000000 + 2 * 60 * 1000);
      expect(result.protocolVersion).toBe("1.0");
      expect(result.legacyFirstFactor).toBe(false);
    }
  });

  it("should store the challenge in the repository", async () => {
    const repository = createInMemoryChallengeRepository();
    const { useCase } = createUseCase({ repository });

    await useCase.execute(validChallengeRequest());

    expect(repository.challenges.size).toBe(1);
  });

  it("should publish a ChallengeIssued event", async () => {
    const eventPublisher = createCapturingEventPublisher();
    const { useCase } = createUseCase({ eventPublisher });

    await useCase.execute(validChallengeRequest());

    expect(eventPublisher.events).toHaveLength(1);
    const event = eventPublisher.events[0]!;
    expect(event.eventType).toBe("ChallengeIssued");
    expect((event as any).expiresAtMs).toBe(1000000 + 2 * 60 * 1000);
    expect((event as any).clientIdentifier).toBe("alice-payment-service");
  });

  it("should invalidate previous pending challenge and publish ChallengeInvalidated", async () => {
    const repository = createInMemoryChallengeRepository();
    const eventPublisher = createCapturingEventPublisher();
    const { useCase } = createUseCase({ repository, eventPublisher });

    await useCase.execute(validChallengeRequest());
    await useCase.execute(validChallengeRequest());

    const pendingChallenges = [...repository.challenges.values()].filter(
      (c) => c.status === "pending",
    );
    expect(pendingChallenges).toHaveLength(1);
    expect(eventPublisher.events.some((e) => e.eventType === "ChallengeInvalidated")).toBe(true);
  });

  it("should refuse with challenge_refused for invalid credential (indistinguishable)", async () => {
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ valid: false }),
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
  });

  it("should record failed attempt for invalid credential", async () => {
    const clientStatusChecker = createStubClientStatusChecker();
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ valid: false }),
      clientStatusChecker,
    });

    await useCase.execute(validChallengeRequest());

    expect(clientStatusChecker.failedAttempts).toHaveLength(1);
  });

  it("should refuse with challenge_refused for revoked client (indistinguishable) without recording failed attempt", async () => {
    const clientStatusChecker = createStubClientStatusChecker();
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ clientStatus: "revoked", valid: true }),
      clientStatusChecker,
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
    // Failed attempt should NOT be recorded for revoked clients — only for invalid credentials
    expect(clientStatusChecker.failedAttempts).toHaveLength(0);
  });

  it("should audit log revoked client attempt", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ clientStatus: "revoked", valid: true }),
      auditLogger,
    });

    await useCase.execute(validChallengeRequest());

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "CLIENT_REVOKED" });
  });

  it("should refuse with indistinguishable challenge_refused for locked-out client", async () => {
    const { useCase } = createUseCase({
      clientStatusChecker: createStubClientStatusChecker({ isLockedOut: true }),
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      // Must be indistinguishable from invalid credential / revoked / unknown
      expect(result.error).toBe("challenge_refused");
    }
  });

  it("should refuse with rate_limited when rate limit exceeded and log audit with reason", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({
      rateLimiter: createStubRateLimiter(false),
      auditLogger,
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("rate_limited");
    }
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "rate_limited" });
  });

  it("should refuse with unsupported_protocol_version and list supported versions", async () => {
    const { useCase } = createUseCase();

    const request = {
      ...validChallengeRequest(),
      protocolVersion: "0.1-deprecated",
    };
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("unsupported_protocol_version");
      expect(result.supportedVersions).toEqual(["1.0"]);
    }
  });

  it("should default to latest version when no protocol version specified", async () => {
    const { useCase } = createUseCase();

    const request = {
      ...validChallengeRequest(),
      protocolVersion: undefined,
    };
    const result = await useCase.execute(request);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.protocolVersion).toBe("1.0");
    }
  });

  it("should issue challenge with legacy flag when migration is active", async () => {
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ isLegacyApiKey: true }),
      legacyMigrationActive: true,
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.legacyFirstFactor).toBe(true);
    }
  });

  it("should refuse legacy API key when migration period is over", async () => {
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ isLegacyApiKey: true }),
      legacyMigrationActive: false,
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
  });

  it("should audit log every challenge refusal", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ valid: false }),
      auditLogger,
    });

    await useCase.execute(validChallengeRequest());

    expect(auditLogger.entries.length).toBeGreaterThanOrEqual(1);
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "INVALID_CREDENTIAL" });
  });

  it("should audit log every successful challenge issuance with details", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    await useCase.execute(validChallengeRequest());

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("challenge_issued");
    expect(auditLogger.entries[0]!.details["challengeId"]).toBeDefined();
    expect(auditLogger.entries[0]!.details["firstFactorType"]).toBe("zkp");
    expect(auditLogger.entries[0]!.details["legacyFirstFactor"]).toBe(false);
  });

  it("should publish ChallengeIssued event AFTER writing audit log", async () => {
    const ordering: string[] = [];
    const auditLogger = createCapturingAuditLogger();
    const originalLog = auditLogger.log.bind(auditLogger);
    auditLogger.log = async (entry) => {
      ordering.push(`audit:${entry.action}`);
      return originalLog(entry);
    };
    const eventPublisher = createCapturingEventPublisher();
    const originalPublish = eventPublisher.publish.bind(eventPublisher);
    eventPublisher.publish = async (event) => {
      ordering.push(`event:${event.eventType}`);
      return originalPublish(event);
    };
    const { useCase } = createUseCase({ auditLogger, eventPublisher });

    await useCase.execute(validChallengeRequest());

    const auditIndex = ordering.indexOf("audit:challenge_issued");
    const eventIndex = ordering.indexOf("event:ChallengeIssued");
    expect(auditIndex).toBeGreaterThanOrEqual(0);
    expect(eventIndex).toBeGreaterThanOrEqual(0);
    expect(auditIndex).toBeLessThan(eventIndex);
  });

  it("should refuse with service_unavailable when repository capacity is at 100%", async () => {
    const repository = createInMemoryChallengeRepository();
    repository.capacityPercentage = async () => 100;
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ repository, auditLogger });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("service_unavailable");
    }
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "service_unavailable" });
  });

  it("should allow challenge issuance when repository capacity is below 100%", async () => {
    const repository = createInMemoryChallengeRepository();
    repository.capacityPercentage = async () => 99;
    const { useCase } = createUseCase({ repository });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(true);
  });

  it("should refuse with challenge_refused when clientIdentifier is empty", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const request = { ...validChallengeRequest(), clientIdentifier: "" };
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "invalid_client_identifier" });
  });

  it("should refuse with challenge_refused when clientIdentifier exceeds 256 bytes", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const longIdentifier = "a".repeat(257);
    const request = { ...validChallengeRequest(), clientIdentifier: longIdentifier };
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
  });

  it("should accept clientIdentifier of exactly 256 bytes", async () => {
    const { useCase } = createUseCase();

    const maxIdentifier = "a".repeat(256);
    const request = { ...validChallengeRequest(), clientIdentifier: maxIdentifier };
    const result = await useCase.execute(request);

    expect(result.success).toBe(true);
  });

  it("should audit log when invalidating a previous pending challenge", async () => {
    const auditLogger = createCapturingAuditLogger();
    const repository = createInMemoryChallengeRepository();
    const { useCase } = createUseCase({ auditLogger, repository });

    await useCase.execute(validChallengeRequest());
    auditLogger.entries.length = 0; // Clear first issuance audit entries

    await useCase.execute(validChallengeRequest());

    const invalidationEntry = auditLogger.entries.find(
      (e) => e.action === "challenge_invalidated",
    );
    expect(invalidationEntry).toBeDefined();
    expect(invalidationEntry!.clientIdentifier).toBe("alice-payment-service");
    expect(invalidationEntry!.details["challengeId"]).toBeDefined();
  });

  it("should refuse with challenge_refused when channelBinding is empty", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const request = {
      ...validChallengeRequest(),
      channelBinding: new Uint8Array(0),
    };
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
    expect(auditLogger.entries[0]!.action).toBe("challenge_refused");
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "invalid_channel_binding" });
  });

  it("should refuse with challenge_refused when channelBinding has invalid size", async () => {
    const auditLogger = createCapturingAuditLogger();
    const { useCase } = createUseCase({ auditLogger });

    const request = {
      ...validChallengeRequest(),
      channelBinding: new Uint8Array(16).fill(0xaa),
    };
    const result = await useCase.execute(request);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
    expect(auditLogger.entries[0]!.details).toEqual({ reason: "invalid_channel_binding" });
  });

  it("should refuse with challenge_refused for unknown client (indistinguishable)", async () => {
    const { useCase } = createUseCase({
      credentialVerifier: createStubCredentialVerifier({ clientStatus: "unknown", valid: false }),
    });

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("challenge_refused");
    }
  });
});
