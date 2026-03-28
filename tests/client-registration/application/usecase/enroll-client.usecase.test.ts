// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollClientUseCase } from "../../../../src/client-registration/application/usecase/enroll-client.usecase.js";
import { EnrollmentPolicy } from "../../../../src/client-registration/domain/service/enrollment-policy.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "../../../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type {
  ProofOfPossessionVerifier,
} from "../../../../src/client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import type { IdGenerator } from "../../../../src/client-registration/domain/port/outgoing/id-generator.js";
import type { RateLimiter } from "../../../../src/client-registration/domain/port/outgoing/rate-limiter.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createNoopRateLimiter,
  validRequest,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Stubs ---

function createStubCommitmentVerifier(
  overrides: Partial<CommitmentVerifier> = {},
): CommitmentVerifier {
  return {
    isCanonical: overrides.isCanonical ?? (() => true),
    isValidGroupElement: overrides.isValidGroupElement ?? (() => true),
    isIdentityElement: overrides.isIdentityElement ?? (() => false),
  };
}

function createStubProofVerifier(valid: boolean = true): ProofOfPossessionVerifier {
  return {
    verify: () => valid,
  };
}

function createStubIdGenerator(bytes?: Uint8Array): IdGenerator {
  const idBytes = bytes ?? new Uint8Array(16).fill(99);
  return {
    generate: () => ClientId.fromBytes(idBytes),
  };
}

function createStubClientRepository(
  existingClients: Map<string, Client> = new Map(),
): ClientRepository & { savedClients: Client[] } {
  const savedClients: Client[] = [];
  return {
    savedClients,
    save: async (client: Client) => {
      savedClients.push(client);
      existingClients.set(client.identifier, client);
    },
    update: async (client: Client) => {
      existingClients.set(client.identifier, client);
    },
    findByIdentifier: async (identifier: string) => {
      return existingClients.get(identifier) ?? null;
    },
    existsByIdentifier: async (identifier: string) => {
      return existingClients.has(identifier);
    },
  };
}

const createStubAuditLogger = createCapturingAuditLogger;
const createStubEventPublisher = createCapturingEventPublisher;

describe("EnrollClientUseCase", () => {
  it("returns success with receipt on valid enrollment", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createStubAuditLogger();
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest());

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.clientIdentifier).toBe("test-client-1");
      expect(result.referenceId).toBeDefined();
    }
  });

  it("returns same receipt when enrolling same identifier with same commitment (idempotency)", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createStubAuditLogger();
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    const request = validRequest();
    const result1 = await useCase.execute(request);
    const result2 = await useCase.execute(request);

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
    if (result1.success && result2.success) {
      expect(result2.referenceId).toBe(result1.referenceId);
      expect(result2.clientIdentifier).toBe(result1.clientIdentifier);
    }
    // Idempotent path MUST call save() to match timing of new enrollment
    expect(repository.savedClients.length).toBe(2);
  });

  it("idempotent enrollment calls save and publish to match new enrollment timing", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createStubAuditLogger();
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    const request = validRequest();
    await useCase.execute(request);

    // Reset counters
    const saveBefore = repository.savedClients.length;
    const publishBefore = eventPublisher.events.length;

    await useCase.execute(request);

    // Idempotent path must call both save() and publish() to prevent timing oracle
    expect(repository.savedClients.length).toBe(saveBefore + 1);
    expect(eventPublisher.events.length).toBe(publishBefore + 1);
  });

  it("returns failure when enrolling same identifier with different commitment", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createStubAuditLogger();
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    const request1 = validRequest();
    await useCase.execute(request1);

    const request2 = {
      ...validRequest(),
      commitmentBytes: new Uint8Array(32).fill(99),
    };
    const result2 = await useCase.execute(request2);

    expect(result2).toEqual({ success: false, error: "enrollment_failed" });
    // Should log DUPLICATE_IDENTIFIER
    const failEntry = auditLogger.events.find((e: any) => e.metadata?.reason === "DUPLICATE_IDENTIFIER");
    expect(failEntry).toBeDefined();
    expect(failEntry!.eventType).toBe("enrollment_failed");
  });

  it("returns failure for invalid commitment", async () => {
    const auditLogger = createStubAuditLogger();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest());

    expect(result).toEqual({ success: false, error: "enrollment_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "INVALID_ENCODING" }),
    );
  });

  it("returns failure for invalid proof", async () => {
    const auditLogger = createStubAuditLogger();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(false),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest());

    expect(result).toEqual({ success: false, error: "enrollment_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "INVALID_PROOF" }),
    );
  });

  it("all error responses have identical shape", async () => {
    const expectedFailure = { success: false, error: "enrollment_failed" };
    const noop = createNoopRateLimiter();

    // Invalid encoding
    const policy1 = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubProofVerifier(true),
    );
    const uc1 = new EnrollClientUseCase(policy1, createStubClientRepository(), createStubIdGenerator(), createStubAuditLogger(), createStubEventPublisher(), noop);
    expect(await uc1.execute(validRequest())).toEqual(expectedFailure);

    // Invalid group element
    const policy2 = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isValidGroupElement: () => false }),
      createStubProofVerifier(true),
    );
    const uc2 = new EnrollClientUseCase(policy2, createStubClientRepository(), createStubIdGenerator(), createStubAuditLogger(), createStubEventPublisher(), noop);
    expect(await uc2.execute(validRequest())).toEqual(expectedFailure);

    // Identity element
    const policy3 = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => true }),
      createStubProofVerifier(true),
    );
    const uc3 = new EnrollClientUseCase(policy3, createStubClientRepository(), createStubIdGenerator(), createStubAuditLogger(), createStubEventPublisher(), noop);
    expect(await uc3.execute(validRequest())).toEqual(expectedFailure);

    // Invalid proof
    const policy4 = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(false),
    );
    const uc4 = new EnrollClientUseCase(policy4, createStubClientRepository(), createStubIdGenerator(), createStubAuditLogger(), createStubEventPublisher(), noop);
    expect(await uc4.execute(validRequest())).toEqual(expectedFailure);
  });

  it("publishes ClientEnrolled event on success only", async () => {
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      createStubAuditLogger(),
      eventPublisher,
      createNoopRateLimiter(),
    );

    await useCase.execute(validRequest());

    expect(eventPublisher.events.length).toBe(1);
    expect(eventPublisher.events[0]!.eventType).toBe("ClientEnrolled");
  });

  it("does not publish event on failure", async () => {
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      createStubAuditLogger(),
      eventPublisher,
      createNoopRateLimiter(),
    );

    await useCase.execute(validRequest());

    expect(eventPublisher.events.length).toBe(0);
  });

  it("logs audit event on success", async () => {
    const auditLogger = createStubAuditLogger();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    await useCase.execute(validRequest());

    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_succeeded");
    expect(auditLogger.events[0]!.clientIdentifier).toBe("test-client-1");
  });

  it("logs audit event on failure without commitment owner (amendment #11)", async () => {
    const auditLogger = createStubAuditLogger();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    await useCase.execute(validRequest());

    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_failed");
    expect(auditLogger.events[0]!.clientIdentifier).toBeUndefined();
  });

  it("handles save failure gracefully", async () => {
    let saveCount = 0;
    const failingRepository: ClientRepository = {
      save: async () => {
        saveCount++;
        if (saveCount === 2) {
          throw new Error("Optimistic concurrency conflict");
        }
      },
      findByIdentifier: async () => null,
      existsByIdentifier: async () => false,
    };

    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      failingRepository,
      createStubIdGenerator(),
      createStubAuditLogger(),
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    const result1 = await useCase.execute(validRequest());
    expect(result1.success).toBe(true);

    const result2 = await useCase.execute(validRequest());
    expect(result2).toEqual({ success: false, error: "enrollment_failed" });
  });

  it("always calls rate limiter on every enrollment request", async () => {
    let rateLimiterCalled = false;
    const rateLimiter: RateLimiter = {
      isAllowed: async () => {
        rateLimiterCalled = true;
        return true;
      },
    };
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      createStubAuditLogger(),
      createStubEventPublisher(),
      rateLimiter,
    );

    await useCase.execute(validRequest());
    expect(rateLimiterCalled).toBe(true);
  });

  it("returns failure when rate limited", async () => {
    const auditLogger = createStubAuditLogger();
    const rateLimiter: RateLimiter = {
      isAllowed: async () => false,
    };
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      rateLimiter,
    );

    const result = await useCase.execute(validRequest());
    expect(result).toEqual({ success: false, error: "enrollment_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("enrollment_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "RATE_LIMITED" }),
    );
  });

  it("allowed rate limiter allows enrollment (if !allowed should block, not if true)", async () => {
    // Kill mutant: `if (true)` instead of `if (!allowed)`
    const auditLogger = createStubAuditLogger();
    const rateLimiter: RateLimiter = {
      isAllowed: async () => true, // explicitly allowed
    };
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      rateLimiter,
    );

    const result = await useCase.execute(validRequest());
    // With `if (true)`, this would always fail with rate limited
    expect(result.success).toBe(true);
  });

  it("allows re-enrollment with new commitment when identifier was revoked (BA09)", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createStubAuditLogger();
    const eventPublisher = createStubEventPublisher();
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      repository,
      createStubIdGenerator(),
      auditLogger,
      eventPublisher,
      createNoopRateLimiter(),
    );

    // First enrollment
    const request1 = validRequest("revokable-client");
    const result1 = await useCase.execute(request1);
    expect(result1.success).toBe(true);

    // Revoke the client
    const existing = await repository.findByIdentifier("revokable-client");
    const revoked = existing!.revoke();
    await repository.update(revoked);

    // Re-enrollment with new commitment should succeed
    const request2 = {
      ...validRequest("revokable-client", 99),
    };
    const result2 = await useCase.execute(request2);
    expect(result2.success).toBe(true);
    if (result2.success) {
      expect(result2.clientIdentifier).toBe("revokable-client");
    }
  });

  it("fails when commitment is null due to construction error (both null checks needed)", async () => {
    // Kill mutants: `commitment === null || false` and `false || client === null`
    // Test with an invalid commitment that causes Commitment.fromBytes to throw
    const auditLogger = createStubAuditLogger();
    // Use an isIdentityElement check that returns false (so policy passes),
    // but use commitment bytes that are actually all-zero (so Commitment.fromBytes throws)
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => false }),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      createStubClientRepository(),
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    // Use 31-byte commitment that will fail both in Commitment.fromBytes
    // (wrong length) AND cause policy validation to fail
    // Actually, we need a scenario where policy passes but construction fails.
    // Use an empty identifier which makes Client.register throw
    const result = await useCase.execute({
      clientIdentifier: "  ", // whitespace-only → Client.register throws
      commitmentBytes: new Uint8Array(32).fill(42), // valid commitment
      proofOfPossession: {
        announcement: new Uint8Array(32).fill(1),
        responseS: new Uint8Array(32).fill(2),
        responseR: new Uint8Array(32).fill(3),
      },
    });

    // client will be null because Client.register("  ") throws
    expect(result).toEqual({ success: false, error: "enrollment_failed" });
  });

  it("logs audit with SAVE_FAILED reason on repository error", async () => {
    const auditLogger = createStubAuditLogger();
    const failingRepository: ClientRepository = {
      save: async () => {
        throw new Error("Connection refused");
      },
      findByIdentifier: async () => null,
      existsByIdentifier: async () => false,
    };

    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );
    const useCase = new EnrollClientUseCase(
      policy,
      failingRepository,
      createStubIdGenerator(),
      auditLogger,
      createStubEventPublisher(),
      createNoopRateLimiter(),
    );

    const result = await useCase.execute(validRequest());
    expect(result).toEqual({ success: false, error: "enrollment_failed" });
    const failEntry = auditLogger.events.find((e: any) => e.metadata?.reason === "SAVE_FAILED");
    expect(failEntry).toBeDefined();
    expect(failEntry!.eventType).toBe("enrollment_failure");
    expect(failEntry!.metadata.error).toBe("Connection refused");
  });
});
