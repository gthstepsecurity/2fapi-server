// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  createEnrollmentService,
  createLifecycleService,
  InMemoryClientRepository,
  StubCommitmentVerifier,
  StubProofOfPossessionVerifier,
  CryptoRandomIdGenerator,
  NoopEventPublisher,
  NoopRateLimiter,
  StubTokenInvalidator,
  StubChallengeInvalidator,
  StubRotationProofVerifier,
} from "../../src/index.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  validRequest,
} from "../helpers/enrollment-test-helpers.js";
import {
  TestAdminAuthenticator,
  validRevokeRequest,
  validRotateRequest,
} from "../helpers/lifecycle-test-helpers.js";

describe("Client Lifecycle — Acceptance Tests", () => {
  describe("Revocation", () => {
    it("happy path: enrolled client is revoked, tokens and challenges invalidated", async () => {
      const repository = new InMemoryClientRepository();
      const auditLogger = createCapturingAuditLogger();
      const eventPublisher = createCapturingEventPublisher();

      // Step 1: Enroll
      const enrollService = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger,
        eventPublisher,
        rateLimiter: new NoopRateLimiter(),
      });

      const enrollResult = await enrollService.execute(validRequest("revoke-target"));
      expect(enrollResult.success).toBe(true);

      // Step 2: Revoke
      const tokenInvalidator = new StubTokenInvalidator();
      const challengeInvalidator = new StubChallengeInvalidator();
      const revokeAudit = createCapturingAuditLogger();
      const revokeEvents = createCapturingEventPublisher();

      const { revokeClient } = createLifecycleService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator,
        challengeInvalidator,
        auditLogger: revokeAudit,
        eventPublisher: revokeEvents,
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      const revokeResult = await revokeClient.execute(validRevokeRequest("revoke-target"));
      expect(revokeResult).toEqual({ success: true });

      // Verify client is revoked
      const storedClient = await repository.findByIdentifier("revoke-target");
      expect(storedClient!.status).toBe("revoked");

      // Verify tokens invalidated
      expect(tokenInvalidator.invalidatedClients).toContain("revoke-target");

      // Verify event published
      expect(revokeEvents.events.length).toBe(1);
      expect(revokeEvents.events[0]!.eventType).toBe("ClientRevoked");

      // Verify audit logged
      expect(revokeAudit.events.some((e) => e.eventType === "client_revoked")).toBe(true);
    });

    it("revocation is idempotent", async () => {
      const repository = new InMemoryClientRepository();
      const auditLogger = createCapturingAuditLogger();

      const enrollService = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger,
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      await enrollService.execute(validRequest("idem-client"));

      const { revokeClient } = createLifecycleService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result1 = await revokeClient.execute(validRevokeRequest("idem-client"));
      const result2 = await revokeClient.execute(validRevokeRequest("idem-client"));

      expect(result1).toEqual({ success: true });
      expect(result2).toEqual({ success: true });
    });

    it("revoking unknown client is indistinguishable from success", async () => {
      const { revokeClient } = createLifecycleService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await revokeClient.execute(validRevokeRequest("ghost-client"));
      expect(result).toEqual({ success: true });
    });

    it("revocation without admin identity fails", async () => {
      const { revokeClient } = createLifecycleService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await revokeClient.execute({
        clientIdentifier: "any-client",
        adminIdentity: "",
      });

      expect(result).toEqual({ success: false, error: "revocation_failed" });
    });
  });

  describe("Commitment Rotation", () => {
    it("happy path: enrolled client rotates commitment", async () => {
      const repository = new InMemoryClientRepository();
      const auditLogger = createCapturingAuditLogger();

      const enrollService = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger,
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      await enrollService.execute(validRequest("rotate-target", 42));

      const tokenInvalidator = new StubTokenInvalidator();
      const challengeInvalidator = new StubChallengeInvalidator();
      const rotateAudit = createCapturingAuditLogger();
      const rotateEvents = createCapturingEventPublisher();

      const { rotateCommitment } = createLifecycleService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator,
        challengeInvalidator,
        auditLogger: rotateAudit,
        eventPublisher: rotateEvents,
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await rotateCommitment.execute(validRotateRequest("rotate-target", 0xcd));

      expect(result).toEqual({ success: true });

      // Verify new commitment stored
      const storedClient = await repository.findByIdentifier("rotate-target");
      expect(storedClient!.commitment.toBytes()).toEqual(new Uint8Array(32).fill(0xcd));

      // Verify tokens invalidated
      expect(tokenInvalidator.invalidatedClients).toContain("rotate-target");

      // Verify event published
      expect(rotateEvents.events.length).toBe(1);
      expect(rotateEvents.events[0]!.eventType).toBe("CommitmentRotated");

      // Verify audit logged
      expect(rotateAudit.events.some((e) => e.eventType === "commitment_rotated")).toBe(true);
    });

    it("rotation of revoked client fails", async () => {
      const repository = new InMemoryClientRepository();
      const auditLogger = createCapturingAuditLogger();

      const enrollService = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger,
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      await enrollService.execute(validRequest("doomed-client", 42));

      const { revokeClient, rotateCommitment } = createLifecycleService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      await revokeClient.execute(validRevokeRequest("doomed-client"));
      const result = await rotateCommitment.execute(validRotateRequest("doomed-client"));

      expect(result).toEqual({ success: false, error: "rotation_failed" });
    });

    it("rotation with same commitment fails", async () => {
      const repository = new InMemoryClientRepository();
      const auditLogger = createCapturingAuditLogger();

      const enrollService = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger,
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      await enrollService.execute(validRequest("same-commit-client", 42));

      const { rotateCommitment } = createLifecycleService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      // Same commitment byte as enrollment
      const result = await rotateCommitment.execute(validRotateRequest("same-commit-client", 42));

      expect(result).toEqual({ success: false, error: "rotation_failed" });
    });

    it("all rotation error responses are indistinguishable", async () => {
      const expectedFailure = { success: false, error: "rotation_failed" };

      // Unknown client
      const { rotateCommitment: rc1 } = createLifecycleService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(true),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      expect(await rc1.execute(validRotateRequest("unknown"))).toEqual(expectedFailure);

      // Invalid proof
      const repo2 = new InMemoryClientRepository();
      const enrollService2 = createEnrollmentService({
        clientRepository: repo2,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });
      await enrollService2.execute(validRequest("bad-proof-client"));

      const { rotateCommitment: rc2 } = createLifecycleService({
        clientRepository: repo2,
        commitmentVerifier: new StubCommitmentVerifier(),
        rotationProofVerifier: new StubRotationProofVerifier(false),
        tokenInvalidator: new StubTokenInvalidator(),
        challengeInvalidator: new StubChallengeInvalidator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: createCapturingEventPublisher(),
        adminAuthenticator: new TestAdminAuthenticator(),
        rateLimiter: new NoopRateLimiter(),
      });

      expect(await rc2.execute(validRotateRequest("bad-proof-client"))).toEqual(expectedFailure);
    });
  });
});
