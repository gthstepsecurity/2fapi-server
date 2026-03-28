// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ReactivateViaExternalUseCase } from "../../../../src/client-registration/application/usecase/reactivate-via-external.usecase.js";
import type { ReactivateViaExternalRequest } from "../../../../src/client-registration/domain/port/incoming/reactivate-via-external.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { RecoveryHashStore } from "../../../../src/client-registration/domain/port/outgoing/recovery-hash-store.js";
import type { AdminAuthenticator } from "../../../../src/client-registration/domain/port/outgoing/admin-authenticator.js";
import type { TokenInvalidator } from "../../../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";
import type { ReactivationProofVerifier } from "../../../../src/client-registration/application/usecase/reactivate-via-external.usecase.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Test Helpers ---

function createSuspendedClient(identifier: string = "alice-payment-service"): Client {
  const active = Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
  return active.suspend();
}

function createActiveClient(identifier: string = "alice-payment-service"): Client {
  return Client.register(
    ClientId.fromBytes(new Uint8Array(16).fill(7)),
    identifier,
    Commitment.fromBytes(new Uint8Array(32).fill(0xab)),
  );
}

function createStubClientRepository(
  clients: Map<string, Client> = new Map(),
): ClientRepository & { updatedClients: Client[] } {
  const updatedClients: Client[] = [];
  return {
    updatedClients,
    save: async () => {},
    update: async (client: Client) => {
      updatedClients.push(client);
      clients.set(client.identifier, client);
    },
    findByIdentifier: async (identifier: string) => clients.get(identifier) ?? null,
    existsByIdentifier: async (identifier: string) => clients.has(identifier),
  };
}

function createStubRecoveryHashStore(
  failedAttempts: Map<string, number> = new Map(),
  hashes: Map<string, Uint8Array> = new Map(),
): RecoveryHashStore & { attempts: Map<string, number>; storedHashes: Map<string, Uint8Array> } {
  return {
    attempts: failedAttempts,
    storedHashes: hashes,
    storeHash: async (clientIdentifier: string, hash: Uint8Array) => {
      hashes.set(clientIdentifier, hash);
    },
    getHash: async (clientIdentifier: string) => hashes.get(clientIdentifier) ?? null,
    recordFailedAttempt: async (clientIdentifier: string) => {
      const current = failedAttempts.get(clientIdentifier) ?? 0;
      const next = current + 1;
      failedAttempts.set(clientIdentifier, next);
      return next;
    },
    resetAttempts: async (clientIdentifier: string) => {
      failedAttempts.set(clientIdentifier, 0);
    },
    getAttemptCount: async (clientIdentifier: string) => {
      return failedAttempts.get(clientIdentifier) ?? 0;
    },
    deleteHash: async (clientIdentifier: string) => {
      hashes.delete(clientIdentifier);
      failedAttempts.delete(clientIdentifier);
    },
  };
}

function createStubAdminAuthenticator(
  validAdmins: Set<string> = new Set(["bob-admin-id"]),
): AdminAuthenticator {
  return {
    isValidAdmin: async (adminIdentity: string) => validAdmins.has(adminIdentity),
  };
}

function createStubTokenInvalidator(): TokenInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

function createStubChallengeInvalidator(): ChallengeInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

function createStubProofVerifier(valid: boolean = true): ReactivationProofVerifier {
  return {
    verify: () => valid,
  };
}

function validReactivateRequest(
  identifier: string = "alice-payment-service",
  adminIdentity: string = "bob-admin-id",
): ReactivateViaExternalRequest {
  return {
    clientIdentifier: identifier,
    adminIdentity,
    newCommitmentBytes: new Uint8Array(32).fill(0xbb),
    newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
  };
}

function createUseCase(overrides: {
  adminAuthenticator?: AdminAuthenticator;
  repository?: ClientRepository;
  recoveryHashStore?: RecoveryHashStore;
  tokenInvalidator?: TokenInvalidator;
  challengeInvalidator?: ChallengeInvalidator;
  auditLogger?: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher?: ReturnType<typeof createCapturingEventPublisher>;
  proofVerifier?: ReactivationProofVerifier;
} = {}) {
  return new ReactivateViaExternalUseCase(
    overrides.adminAuthenticator ?? createStubAdminAuthenticator(),
    overrides.repository ?? createStubClientRepository(),
    overrides.recoveryHashStore ?? createStubRecoveryHashStore(),
    overrides.tokenInvalidator ?? createStubTokenInvalidator(),
    overrides.challengeInvalidator ?? createStubChallengeInvalidator(),
    overrides.auditLogger ?? createCapturingAuditLogger(),
    overrides.eventPublisher ?? createCapturingEventPublisher(),
    overrides.proofVerifier ?? createStubProofVerifier(true),
  );
}

describe("ReactivateViaExternalUseCase", () => {
  describe("successful reactivation", () => {
    it("admin reactivates suspended client with new commitment", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);

      const useCase = createUseCase({ repository });

      const result = await useCase.execute(validReactivateRequest());

      expect(result).toEqual({ success: true });
    });

    it("client status changes to active with new commitment", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);

      const useCase = createUseCase({ repository });

      await useCase.execute(validReactivateRequest());

      expect(repository.updatedClients.length).toBe(1);
      expect(repository.updatedClients[0]!.status).toBe("active");
      expect(repository.updatedClients[0]!.commitment.toBytes()).toEqual(new Uint8Array(32).fill(0xbb));
    });

    it("resets failed attempt counter and lockout", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const failedAttempts = new Map([["alice-payment-service", 3]]);
      const recoveryHashStore = createStubRecoveryHashStore(failedAttempts);

      const useCase = createUseCase({ repository, recoveryHashStore });

      await useCase.execute(validReactivateRequest());

      expect(recoveryHashStore.attempts.get("alice-payment-service")).toBe(0);
    });

    it("publishes ClientReactivated event with admin identity", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const eventPublisher = createCapturingEventPublisher();

      const useCase = createUseCase({ repository, eventPublisher });

      await useCase.execute(validReactivateRequest());

      expect(eventPublisher.events.length).toBe(1);
      expect(eventPublisher.events[0]!.eventType).toBe("ClientReactivated");
    });

    it("logs reactivation in audit trail with admin identity", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({ repository, auditLogger });

      await useCase.execute(validReactivateRequest());

      const auditEvent = auditLogger.events.find((e) => e.eventType === "client_reactivated");
      expect(auditEvent).toBeDefined();
      expect(auditEvent!.clientIdentifier).toBe("alice-payment-service");
      expect(auditEvent!.metadata).toEqual(
        expect.objectContaining({ adminIdentity: "bob-admin-id" }),
      );
    });

    it("invalidates old tokens and challenges", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const tokenInvalidator = createStubTokenInvalidator();
      const challengeInvalidator = createStubChallengeInvalidator();

      const useCase = createUseCase({
        repository,
        tokenInvalidator,
        challengeInvalidator,
      });

      await useCase.execute(validReactivateRequest());

      expect(tokenInvalidator.invalidatedClients).toEqual(["alice-payment-service"]);
      expect(challengeInvalidator.invalidatedClients).toEqual(["alice-payment-service"]);
    });
  });

  describe("reactivation failures", () => {
    it("unauthenticated admin: returns reactivation_failed", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({
        repository,
        adminAuthenticator: createStubAdminAuthenticator(new Set(["bob-admin-id"])),
        auditLogger,
      });

      const result = await useCase.execute(validReactivateRequest("alice-payment-service", "attacker-eve"));

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
      expect(auditLogger.events[0]!.eventType).toBe("reactivation_failed");
    });

    it("empty admin identity: returns reactivation_failed", async () => {
      const useCase = createUseCase();

      const result = await useCase.execute(validReactivateRequest("alice-payment-service", ""));

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
    });

    it("non-suspended (active) client: returns reactivation_failed", async () => {
      const client = createActiveClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({ repository, auditLogger });

      const result = await useCase.execute(validReactivateRequest());

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
    });

    it("unknown client: returns reactivation_failed", async () => {
      const repository = createStubClientRepository();

      const useCase = createUseCase({ repository });

      const result = await useCase.execute(validReactivateRequest("unknown-client"));

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
    });

    it("after external reactivation, old recovery hash is deleted", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const oldHash = new Uint8Array(32).fill(0xab);
      const hashes = new Map([["alice-payment-service", oldHash]]);
      const recoveryHashStore = createStubRecoveryHashStore(new Map(), hashes);

      const useCase = createUseCase({ repository, recoveryHashStore });

      await useCase.execute(validReactivateRequest());

      // Old recovery hash should be deleted — phrase no longer works
      expect(recoveryHashStore.storedHashes.has("alice-payment-service")).toBe(false);
    });

    it("reactivation without valid commitment proof is refused (BD08)", async () => {
      const client = createSuspendedClient();
      const clients = new Map([["alice-payment-service", client]]);
      const repository = createStubClientRepository(clients);
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({
        repository,
        auditLogger,
        proofVerifier: createStubProofVerifier(false),
      });

      const result = await useCase.execute(validReactivateRequest());

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
      const failEvent = auditLogger.events.find((e: any) => e.metadata?.reason === "INVALID_COMMITMENT_PROOF");
      expect(failEvent).toBeDefined();
    });

    it("admin auth happens before client lookup", async () => {
      const auditLogger = createCapturingAuditLogger();

      const useCase = createUseCase({
        adminAuthenticator: createStubAdminAuthenticator(new Set()),
        auditLogger,
      });

      const result = await useCase.execute(validReactivateRequest("nonexistent", "fake-admin"));

      expect(result).toEqual({ success: false, error: "reactivation_failed" });
      expect(auditLogger.events[0]!.eventType).toBe("reactivation_failed");
      expect(auditLogger.events[0]!.metadata).toEqual(
        expect.objectContaining({ reason: "ADMIN_AUTH_FAILED" }),
      );
    });
  });
});
