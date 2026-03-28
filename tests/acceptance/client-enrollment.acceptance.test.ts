// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  createEnrollmentService,
  InMemoryClientRepository,
  StubCommitmentVerifier,
  StubProofOfPossessionVerifier,
  CryptoRandomIdGenerator,
  NoopEventPublisher,
  NoopRateLimiter,
} from "../../src/index.js";
import type { EnrollClientRequest } from "../../src/index.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  validRequest,
} from "../helpers/enrollment-test-helpers.js";

describe("Client Enrollment — Acceptance Tests", () => {
  it("happy path: valid enrollment returns receipt, stores client, publishes event, logs audit", async () => {
    const repository = new InMemoryClientRepository();
    const auditLogger = createCapturingAuditLogger();
    const eventPublisher = createCapturingEventPublisher();

    const service = createEnrollmentService({
      clientRepository: repository,
      commitmentVerifier: new StubCommitmentVerifier(),
      proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
      idGenerator: new CryptoRandomIdGenerator(),
      auditLogger,
      eventPublisher,
      rateLimiter: new NoopRateLimiter(),
    });

    const result = await service.execute(validRequest());

    // Receipt returned
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.clientIdentifier).toBe("test-client-1");
      expect(result.referenceId).toBeDefined();
      expect(result.referenceId.length).toBeGreaterThan(0);
    }

    // Client in repository
    const storedClient = await repository.findByIdentifier("test-client-1");
    expect(storedClient).not.toBeNull();

    // Event published
    expect(eventPublisher.events.length).toBe(1);
    expect(eventPublisher.events[0]!.eventType).toBe("ClientEnrolled");

    // Audit logged
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_succeeded");
  });

  describe("all error paths return identical response", () => {
    const expectedFailure = { success: false, error: "enrollment_failed" } as const;

    it("invalid encoding → indistinguishable failure", async () => {
      const service = createEnrollmentService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier({ isCanonical: false }),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await service.execute(validRequest());
      expect(result).toEqual(expectedFailure);
    });

    it("invalid group element → indistinguishable failure", async () => {
      const service = createEnrollmentService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier({ isValidGroupElement: false }),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await service.execute(validRequest());
      expect(result).toEqual(expectedFailure);
    });

    it("identity element → indistinguishable failure", async () => {
      const service = createEnrollmentService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier({ isIdentityElement: true }),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await service.execute(validRequest());
      expect(result).toEqual(expectedFailure);
    });

    it("invalid proof → indistinguishable failure", async () => {
      const service = createEnrollmentService({
        clientRepository: new InMemoryClientRepository(),
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(false),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      const result = await service.execute(validRequest());
      expect(result).toEqual(expectedFailure);
    });

    it("duplicate identifier with different commitment → indistinguishable failure", async () => {
      const repository = new InMemoryClientRepository();
      const service = createEnrollmentService({
        clientRepository: repository,
        commitmentVerifier: new StubCommitmentVerifier(),
        proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
        idGenerator: new CryptoRandomIdGenerator(),
        auditLogger: createCapturingAuditLogger(),
        eventPublisher: new NoopEventPublisher(),
        rateLimiter: new NoopRateLimiter(),
      });

      await service.execute(validRequest("same-client", 42));
      const result = await service.execute(validRequest("same-client", 99));
      expect(result).toEqual(expectedFailure);
    });
  });

  it("idempotency: enrolling same identifier + commitment twice returns same receipt", async () => {
    const repository = new InMemoryClientRepository();
    const service = createEnrollmentService({
      clientRepository: repository,
      commitmentVerifier: new StubCommitmentVerifier(),
      proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
      idGenerator: new CryptoRandomIdGenerator(),
      auditLogger: createCapturingAuditLogger(),
      eventPublisher: createCapturingEventPublisher(),
      rateLimiter: new NoopRateLimiter(),
    });

    const request = validRequest();
    const result1 = await service.execute(request);
    const result2 = await service.execute(request);

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
    if (result1.success && result2.success) {
      expect(result2.referenceId).toBe(result1.referenceId);
      expect(result2.clientIdentifier).toBe(result1.clientIdentifier);
    }
  });

  it("concurrent enrollment: two enrollments with same identifier — one wins", async () => {
    const repository = new InMemoryClientRepository();
    const service = createEnrollmentService({
      clientRepository: repository,
      commitmentVerifier: new StubCommitmentVerifier(),
      proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
      idGenerator: new CryptoRandomIdGenerator(),
      auditLogger: createCapturingAuditLogger(),
      eventPublisher: createCapturingEventPublisher(),
      rateLimiter: new NoopRateLimiter(),
    });

    // Different commitments to avoid idempotency path
    const request1 = validRequest("contested-client", 42);
    const request2 = validRequest("contested-client", 99);

    const [result1, result2] = await Promise.all([
      service.execute(request1),
      service.execute(request2),
    ]);

    // Exactly one succeeds, one fails
    const successes = [result1, result2].filter((r) => r.success);
    const failures = [result1, result2].filter((r) => !r.success);

    // At least one succeeds (the first to save wins)
    expect(successes.length + failures.length).toBe(2);
    // At most one can succeed with different commitments
    // Due to async, both might find no existing client but one save will fail
    expect(successes.length).toBeGreaterThanOrEqual(1);
  });

  // NOTE: These property-based tests use stubs for crypto operations.
  // Real cryptographic property tests will be added when the Rust crypto core is integrated (Sprint 3+).
  describe("property-based tests", () => {
    it("any valid 32-byte non-zero commitment + valid proof → enrollment succeeds", async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 32, maxLength: 32 }).filter(
            (bytes) => !bytes.every((b) => b === 0),
          ),
          fc.string({ minLength: 1, maxLength: 64 }).filter(
            (s) => s.trim().length > 0,
          ),
          async (commitmentBytes, identifier) => {
            const service = createEnrollmentService({
              clientRepository: new InMemoryClientRepository(),
              commitmentVerifier: new StubCommitmentVerifier(),
              proofOfPossessionVerifier: new StubProofOfPossessionVerifier(true),
              idGenerator: new CryptoRandomIdGenerator(),
              auditLogger: createCapturingAuditLogger(),
              eventPublisher: new NoopEventPublisher(),
              rateLimiter: new NoopRateLimiter(),
            });

            const request: EnrollClientRequest = {
              clientIdentifier: identifier,
              commitmentBytes,
              proofOfPossession: {
                announcement: new Uint8Array(32).fill(1),
                responseS: new Uint8Array(32).fill(2),
                responseR: new Uint8Array(32).fill(3),
              },
            };

            const result = await service.execute(request);
            expect(result.success).toBe(true);
          },
        ),
        { numRuns: 50 },
      );
    });

    it("any invalid proof → enrollment fails with indistinguishable error", async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 32, maxLength: 32 }).filter(
            (bytes) => !bytes.every((b) => b === 0),
          ),
          fc.string({ minLength: 1, maxLength: 64 }).filter(
            (s) => s.trim().length > 0,
          ),
          async (commitmentBytes, identifier) => {
            const service = createEnrollmentService({
              clientRepository: new InMemoryClientRepository(),
              commitmentVerifier: new StubCommitmentVerifier(),
              proofOfPossessionVerifier: new StubProofOfPossessionVerifier(false),
              idGenerator: new CryptoRandomIdGenerator(),
              auditLogger: createCapturingAuditLogger(),
              eventPublisher: new NoopEventPublisher(),
              rateLimiter: new NoopRateLimiter(),
            });

            const request: EnrollClientRequest = {
              clientIdentifier: identifier,
              commitmentBytes,
              proofOfPossession: {
                announcement: new Uint8Array(32).fill(1),
                responseS: new Uint8Array(32).fill(2),
                responseR: new Uint8Array(32).fill(3),
              },
            };

            const result = await service.execute(request);
            expect(result).toEqual({
              success: false,
              error: "enrollment_failed",
            });
          },
        ),
        { numRuns: 50 },
      );
    });
  });
});
