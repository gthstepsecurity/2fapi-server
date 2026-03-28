// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RevokeClientUseCase } from "../../../../src/client-registration/application/usecase/revoke-client.usecase.js";
import { RevocationPolicy } from "../../../../src/client-registration/domain/service/revocation-policy.js";
import type { ClientRepository } from "../../../../src/client-registration/domain/port/outgoing/client-repository.js";
import type { TokenInvalidator } from "../../../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import type { AdminAuthenticator } from "../../../../src/client-registration/domain/port/outgoing/admin-authenticator.js";
import type { RevokeClientRequest } from "../../../../src/client-registration/domain/port/incoming/revoke-client.js";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../../../helpers/enrollment-test-helpers.js";

// --- Test Helpers ---

function createActiveClient(identifier: string = "client-1"): Client {
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

function createStubAdminAuthenticator(
  validAdmins: Set<string> = new Set(["admin-alice", "admin-bob"]),
): AdminAuthenticator {
  return {
    isValidAdmin: async (adminIdentity: string) => validAdmins.has(adminIdentity),
  };
}

function validRevokeRequest(identifier: string = "client-1"): RevokeClientRequest {
  return {
    clientIdentifier: identifier,
    adminIdentity: "admin-alice",
  };
}

describe("RevokeClientUseCase", () => {
  it("revokes active client: status changed, tokens invalidated, challenges invalidated, event published, audit logged", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);
    const tokenInvalidator = createStubTokenInvalidator();
    const challengeInvalidator = createStubChallengeInvalidator();
    const auditLogger = createCapturingAuditLogger();
    const eventPublisher = createCapturingEventPublisher();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      tokenInvalidator,
      challengeInvalidator,
      auditLogger,
      eventPublisher,
    );

    const result = await useCase.execute(validRevokeRequest());

    expect(result).toEqual({ success: true });

    // Status changed
    expect(repository.updatedClients.length).toBe(1);
    expect(repository.updatedClients[0]!.status).toBe("revoked");

    // Tokens invalidated
    expect(tokenInvalidator.invalidatedClients).toEqual(["client-1"]);

    // Challenges invalidated
    expect(challengeInvalidator.invalidatedClients).toEqual(["client-1"]);

    // Event published
    expect(eventPublisher.events.length).toBe(1);
    expect(eventPublisher.events[0]!.eventType).toBe("ClientRevoked");

    // Audit logged
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("client_revoked");
    expect(auditLogger.events[0]!.clientIdentifier).toBe("client-1");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ adminIdentity: "admin-alice" }),
    );
  });

  it("is idempotent: already revoked client returns success with no state change", async () => {
    const activeClient = createActiveClient();
    const revokedClient = activeClient.revoke();
    const clients = new Map([["client-1", revokedClient]]);
    const repository = createStubClientRepository(clients);
    const tokenInvalidator = createStubTokenInvalidator();
    const challengeInvalidator = createStubChallengeInvalidator();
    const auditLogger = createCapturingAuditLogger();
    const eventPublisher = createCapturingEventPublisher();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      tokenInvalidator,
      challengeInvalidator,
      auditLogger,
      eventPublisher,
    );

    const result = await useCase.execute(validRevokeRequest());

    expect(result).toEqual({ success: true });
    // No state change (no update call)
    expect(repository.updatedClients.length).toBe(0);
    // No event published
    expect(eventPublisher.events.length).toBe(0);
    // Audit still logged for idempotent call
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("client_already_revoked");
    expect(auditLogger.events[0]!.clientIdentifier).toBe("client-1");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ adminIdentity: "admin-alice" }),
    );
    // No tokens invalidated on idempotent call
    expect(tokenInvalidator.invalidatedClients.length).toBe(0);
    expect(challengeInvalidator.invalidatedClients.length).toBe(0);
  });

  it("unknown client: indistinguishable from success", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createCapturingAuditLogger();
    const eventPublisher = createCapturingEventPublisher();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      eventPublisher,
    );

    const result = await useCase.execute(validRevokeRequest("unknown-client"));

    // Indistinguishable from success
    expect(result).toEqual({ success: true });
    // Audit logged
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("revocation_no_such_client");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ adminIdentity: "admin-alice" }),
    );
    // No event published
    expect(eventPublisher.events.length).toBe(0);
  });

  it("no admin identity: returns failure", async () => {
    const repository = createStubClientRepository();
    const auditLogger = createCapturingAuditLogger();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      createCapturingEventPublisher(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      adminIdentity: "",
    });

    expect(result).toEqual({ success: false, error: "revocation_failed" });
    // Audit logged
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("revocation_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "MISSING_ADMIN_IDENTITY" }),
    );
  });

  it("revocation is permanent: no un-revoke path exists", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
    );

    await useCase.execute(validRevokeRequest());
    const storedClient = await repository.findByIdentifier("client-1");
    expect(storedClient!.status).toBe("revoked");

    // No method to un-revoke — Client has no activate() method
    // This is a structural test: we verify the Client class has no such method
    expect("activate" in storedClient!).toBe(false);
    expect("unrevoke" in storedClient!).toBe(false);
  });

  it("audit includes admin identity", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const auditLogger = createCapturingAuditLogger();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      createStubClientRepository(clients),
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      createCapturingEventPublisher(),
    );

    await useCase.execute({
      clientIdentifier: "client-1",
      adminIdentity: "admin-bob",
    });

    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ adminIdentity: "admin-bob" }),
    );
  });

  it("event publisher failure: revocation still succeeds, tokens still invalidated", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);
    const tokenInvalidator = createStubTokenInvalidator();
    const challengeInvalidator = createStubChallengeInvalidator();
    const auditLogger = createCapturingAuditLogger();
    const failingEventPublisher = {
      events: [],
      publish: async () => {
        throw new Error("Event bus unavailable");
      },
    };

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      tokenInvalidator,
      challengeInvalidator,
      auditLogger,
      failingEventPublisher,
    );

    const result = await useCase.execute(validRevokeRequest());

    // Revocation still committed
    expect(result).toEqual({ success: true });
    expect(repository.updatedClients[0]!.status).toBe("revoked");
    // Tokens and challenges still invalidated (they happen BEFORE event)
    expect(tokenInvalidator.invalidatedClients).toEqual(["client-1"]);
    expect(challengeInvalidator.invalidatedClients).toEqual(["client-1"]);
  });

  it("event publisher failure: logs critical audit entry", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);
    const auditLogger = createCapturingAuditLogger();
    const failingEventPublisher = {
      events: [],
      publish: async () => {
        throw new Error("Event bus unavailable");
      },
    };

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      failingEventPublisher,
    );

    await useCase.execute(validRevokeRequest());

    const criticalEvent = auditLogger.events.find(
      (e) => e.eventType === "revocation_event_publish_failed",
    );
    expect(criticalEvent).toBeDefined();
    expect(criticalEvent!.clientIdentifier).toBe("client-1");
  });

  it("all error responses have identical shape", async () => {
    const expectedFailure = { success: false, error: "revocation_failed" };

    // No admin identity
    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(),
      createStubClientRepository(),
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      adminIdentity: "",
    });

    expect(result).toEqual(expectedFailure);
  });

  it("unauthenticated admin identity: returns revocation_refused", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);
    const auditLogger = createCapturingAuditLogger();

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      createStubAdminAuthenticator(new Set(["admin-alice"])),
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      createCapturingEventPublisher(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      adminIdentity: "attacker-eve",
    });

    expect(result).toEqual({ success: false, error: "revocation_failed" });
    // Must NOT have revoked the client
    expect(repository.updatedClients.length).toBe(0);
    // Audit logged with admin auth failure
    expect(auditLogger.events.length).toBe(1);
    expect(auditLogger.events[0]!.eventType).toBe("revocation_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "ADMIN_AUTH_FAILED" }),
    );
  });

  it("invalid admin identity is rejected even when client exists", async () => {
    const activeClient = createActiveClient();
    const clients = new Map([["client-1", activeClient]]);
    const repository = createStubClientRepository(clients);

    // Authenticator that rejects all admins
    const rejectAllAuthenticator: AdminAuthenticator = {
      isValidAdmin: async () => false,
    };

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      rejectAllAuthenticator,
      repository,
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
    );

    const result = await useCase.execute({
      clientIdentifier: "client-1",
      adminIdentity: "anyone",
    });

    expect(result).toEqual({ success: false, error: "revocation_failed" });
    // Client must NOT have been revoked
    const storedClient = await repository.findByIdentifier("client-1");
    expect(storedClient!.status).toBe("active");
  });

  it("admin authentication happens before client lookup", async () => {
    // Even if client does not exist, admin auth should fail first
    const auditLogger = createCapturingAuditLogger();
    const rejectAllAuthenticator: AdminAuthenticator = {
      isValidAdmin: async () => false,
    };

    const useCase = new RevokeClientUseCase(
      new RevocationPolicy(),
      rejectAllAuthenticator,
      createStubClientRepository(),
      createStubTokenInvalidator(),
      createStubChallengeInvalidator(),
      auditLogger,
      createCapturingEventPublisher(),
    );

    const result = await useCase.execute({
      clientIdentifier: "nonexistent",
      adminIdentity: "fake-admin",
    });

    expect(result).toEqual({ success: false, error: "revocation_failed" });
    expect(auditLogger.events[0]!.eventType).toBe("revocation_failed");
    expect(auditLogger.events[0]!.metadata).toEqual(
      expect.objectContaining({ reason: "ADMIN_AUTH_FAILED" }),
    );
  });
});
