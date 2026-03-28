// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { IssueTokenUseCase } from "../../../../src/api-access-control/application/usecase/issue-token.usecase.js";
import { TokenIssuancePolicy } from "../../../../src/api-access-control/domain/service/token-issuance-policy.js";
import { AuthenticationLevel, STANDARD_TTL_MS, ELEVATED_TTL_MS } from "../../../../src/api-access-control/domain/model/authentication-level.js";
import { TokenIssued } from "../../../../src/api-access-control/domain/event/token-issued.js";
import {
  createAllStubs,
  validIssueTokenRequest,
  StubClientStatusChecker,
  StubAuthorizationChecker,
  ISSUER,
} from "../../../helpers/access-control-test-helpers.js";

const NOW_MS = 1000000;

function createUseCase(overrides: Partial<ReturnType<typeof createAllStubs>> = {}) {
  const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS }, ...overrides });
  const policy = new TokenIssuancePolicy();
  const useCase = new IssueTokenUseCase(
    stubs.clientStatusChecker,
    stubs.authorizationChecker,
    stubs.tokenSigner,
    stubs.auditLogger,
    stubs.eventPublisher,
    stubs.clock,
    stubs.idGenerator,
    policy,
    ISSUER,
    stubs.receiptStore,
  );
  return { useCase, stubs };
}

describe("IssueTokenUseCase", () => {
  it("issues a standard token (15 min TTL) on happy path", async () => {
    const { useCase } = createUseCase();
    const response = await useCase.execute(validIssueTokenRequest());

    expect(response.success).toBe(true);
    if (!response.success) return;
    expect(response.bearerToken.length).toBeGreaterThan(0);
    expect(response.expiresAtMs).toBe(NOW_MS + STANDARD_TTL_MS);
  });

  it("issues an elevated token (5 min TTL) for step-up", async () => {
    const { useCase } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ authenticationLevel: AuthenticationLevel.ELEVATED }),
    );

    expect(response.success).toBe(true);
    if (!response.success) return;
    expect(response.expiresAtMs).toBe(NOW_MS + ELEVATED_TTL_MS);
  });

  it("refuses issuance when client is not active", async () => {
    const { useCase } = createUseCase({
      clientStatusChecker: new StubClientStatusChecker(false),
    });
    const response = await useCase.execute(validIssueTokenRequest());

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
  });

  it("refuses issuance when client is not authorized for audience", async () => {
    const { useCase, stubs } = createUseCase({
      authorizationChecker: new StubAuthorizationChecker(false),
    });
    const response = await useCase.execute(validIssueTokenRequest());

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("CLIENT_NOT_AUTHORIZED");
  });

  it("refuses issuance when clientIdentifier is empty", async () => {
    const { useCase, stubs } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ clientIdentifier: "" }),
    );

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_client_identifier");
  });

  it("refuses issuance when clientIdentifier exceeds 256 bytes", async () => {
    const { useCase, stubs } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ clientIdentifier: "x".repeat(257) }),
    );

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_client_identifier");
  });

  it("refuses issuance when audience is empty", async () => {
    const { useCase, stubs } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ audience: "" }),
    );

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_audience");
  });

  it("refuses issuance when channelBindingHash is empty", async () => {
    const { useCase, stubs } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ channelBindingHash: "" }),
    );

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_channel_binding_hash");
  });

  it("logs audit on successful issuance", async () => {
    const { useCase, stubs } = createUseCase();
    await useCase.execute(validIssueTokenRequest());

    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("token_issued");
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
  });

  it("logs audit details on successful issuance (tokenId, audience, level, expiresAtMs)", async () => {
    const { useCase, stubs } = createUseCase();
    await useCase.execute(validIssueTokenRequest());

    const entry = stubs.auditLogger.entries[0]!;
    expect(entry.details.tokenId).toBe("tok-001");
    expect(entry.details.audience).toBe("payment-service");
    expect(entry.details.level).toBe("standard");
    expect(entry.details.expiresAtMs).toBe(NOW_MS + STANDARD_TTL_MS);
  });

  it("logs audit on failed issuance", async () => {
    const { useCase, stubs } = createUseCase({
      clientStatusChecker: new StubClientStatusChecker(false),
    });
    await useCase.execute(validIssueTokenRequest());

    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("issuance_refused");
  });

  it("logs audit details on failed issuance (reason)", async () => {
    const { useCase, stubs } = createUseCase({
      clientStatusChecker: new StubClientStatusChecker(false),
    });
    await useCase.execute(validIssueTokenRequest());

    const entry = stubs.auditLogger.entries[0]!;
    expect(entry.details.reason).toBe("CLIENT_NOT_ACTIVE");
  });

  it("publishes TokenIssued event on success", async () => {
    const { useCase, stubs } = createUseCase();
    await useCase.execute(validIssueTokenRequest());

    expect(stubs.eventPublisher.events.length).toBe(1);
    const event = stubs.eventPublisher.events[0] as TokenIssued;
    expect(event.eventType).toBe("TokenIssued");
    expect(event.clientIdentifier).toBe("alice-payment-service");
    expect(event.audience).toBe("payment-service");
    expect(event.authenticationLevel).toBe("standard");
    expect(event.tokenId).toBe("tok-001");
    expect(event.issuedAtMs).toBe(NOW_MS);
  });

  it("does not publish event on failure", async () => {
    const { useCase, stubs } = createUseCase({
      clientStatusChecker: new StubClientStatusChecker(false),
    });
    await useCase.execute(validIssueTokenRequest());

    expect(stubs.eventPublisher.events.length).toBe(0);
  });

  it("defaults to standard authentication level when not specified", async () => {
    const { useCase, stubs } = createUseCase();
    await useCase.execute(validIssueTokenRequest());

    const event = stubs.eventPublisher.events[0] as TokenIssued;
    expect(event.authenticationLevel).toBe("standard");
  });

  it("accepts clientIdentifier at exactly 256 bytes (boundary)", async () => {
    const id256 = "a".repeat(256);
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    stubs.receiptStore.preload("test-receipt-001", id256);
    const policy = new TokenIssuancePolicy();
    const useCase = new IssueTokenUseCase(
      stubs.clientStatusChecker,
      stubs.authorizationChecker,
      stubs.tokenSigner,
      stubs.auditLogger,
      stubs.eventPublisher,
      stubs.clock,
      stubs.idGenerator,
      policy,
      ISSUER,
      stubs.receiptStore,
    );
    const response = await useCase.execute(
      validIssueTokenRequest({ clientIdentifier: id256 }),
    );

    expect(response.success).toBe(true);
  });

  it("refuses issuance when audience is empty (explicit check)", async () => {
    const { useCase, stubs } = createUseCase();
    const response = await useCase.execute(
      validIssueTokenRequest({ audience: "" }),
    );

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("issuance_refused");
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_audience");
  });
});
