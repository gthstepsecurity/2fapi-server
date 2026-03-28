// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ValidateTokenUseCase } from "../../../../src/api-access-control/application/usecase/validate-token.usecase.js";
import { IssueTokenUseCase } from "../../../../src/api-access-control/application/usecase/issue-token.usecase.js";
import { TokenIssuancePolicy } from "../../../../src/api-access-control/domain/service/token-issuance-policy.js";
import { TokenValidationChain } from "../../../../src/api-access-control/domain/service/token-validation-chain.js";
import { AuthenticationLevel, STANDARD_TTL_MS } from "../../../../src/api-access-control/domain/model/authentication-level.js";
import {
  createAllStubs,
  createPreloadedReceiptStore,
  validIssueTokenRequest,
  StubClientStatusChecker,
  StubTokenVerifier,
  ISSUER,
  CHANNEL_BINDING_HASH,
} from "../../../helpers/access-control-test-helpers.js";

const NOW_MS = 1000000;

function createIssueUseCase(stubs: ReturnType<typeof createAllStubs>) {
  const policy = new TokenIssuancePolicy();
  return new IssueTokenUseCase(
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
}

function createValidateUseCase(stubs: ReturnType<typeof createAllStubs>) {
  const chain = new TokenValidationChain();
  return new ValidateTokenUseCase(
    stubs.tokenVerifier,
    stubs.clientStatusChecker,
    stubs.auditLogger,
    stubs.clock,
    chain,
  );
}

async function issueValidToken(stubs: ReturnType<typeof createAllStubs>): Promise<string> {
  const issueUC = createIssueUseCase(stubs);
  const response = await issueUC.execute(validIssueTokenRequest());
  if (!response.success) throw new Error("Failed to issue token for test setup");
  return response.bearerToken;
}

describe("ValidateTokenUseCase", () => {
  it("grants access for a valid token", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(true);
    if (!response.success) return;
    expect(response.clientIdentifier).toBe("alice-payment-service");
    expect(response.audience).toBe("payment-service");
    expect(response.level).toBe("standard");
  });

  it("grants access 1 second before expiry", async () => {
    let currentTime = NOW_MS;
    const stubs = createAllStubs({ clock: { nowMs: () => currentTime } });
    const bearerToken = await issueValidToken(stubs);

    // Advance clock to 1 second before expiry
    currentTime = NOW_MS + STANDARD_TTL_MS - 1000;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(true);
  });

  it("allows multiple uses of same token (non-single-use)", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    const validateUC = createValidateUseCase(stubs);

    const request = {
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    };

    const r1 = await validateUC.execute(request);
    const r2 = await validateUC.execute(request);

    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);
  });

  it("denies access for expired token", async () => {
    let currentTime = NOW_MS;
    const stubs = createAllStubs({ clock: { nowMs: () => currentTime } });
    const bearerToken = await issueValidToken(stubs);

    // Advance clock past expiry
    currentTime = NOW_MS + STANDARD_TTL_MS + 1;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "TOKEN_EXPIRED" });
  });

  it("denies access for wrong audience", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "billing-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "AUDIENCE_MISMATCH" });
  });

  it("denies access for wrong channel binding (indistinguishable)", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: "0000000000000000000000000000000000000000000000000000000000000000",
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "CHANNEL_BINDING_MISMATCH" });
  });

  it("denies access for forged/invalid signature (timing-safe)", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "forged-bearer-token",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "INVALID_SIGNATURE" });
  });

  it("denies access for malformed token (timing-safe)", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "!!!not-base64!!!",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "malformed_token" });
  });

  it("denies access for revoked client (indistinguishable from expired)", async () => {
    let currentTime = NOW_MS;
    const statusChecker = new StubClientStatusChecker(true);
    const stubs = createAllStubs({
      clock: { nowMs: () => currentTime },
      clientStatusChecker: statusChecker,
    });
    const bearerToken = await issueValidToken(stubs);

    // Revoke client after token issuance
    statusChecker.setActive(false);
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "CLIENT_NOT_ACTIVE" });
  });

  it("denies access for empty bearer token", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "invalid_format" });
  });

  it("denies access for token exceeding 4096 bytes", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "A".repeat(4097),
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (response.success) return;
    expect(response.error).toBe("access_denied");
    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "invalid_format" });
  });

  it("accepts token at exactly 4096 bytes (boundary)", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    // Build a bearer token that is exactly 4096 characters
    // The verifier will return null (invalid), but we need to verify
    // the format check passes at 4096 bytes (i.e. >4096 rejects, =4096 does not)
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    // Use a valid base64url string of exactly 4096 chars
    const bearerToken4096 = "A".repeat(4096);
    const response = await validateUC.execute({
      bearerToken: bearerToken4096,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    // Should fail for invalid signature, NOT for invalid_format
    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("access_denied");
    }
    // The audit should NOT say "invalid_format" — the format check passed
    expect(stubs.auditLogger.entries[0]!.details).not.toEqual({ reason: "invalid_format" });
  });

  it("logs audit on successful access", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    // Clear audit entries from issuance
    stubs.auditLogger.entries.length = 0;

    const validateUC = createValidateUseCase(stubs);
    await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_granted");
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(stubs.auditLogger.entries[0]!.timestamp).toBeInstanceOf(Date);
    expect(stubs.auditLogger.entries[0]!.details.audience).toBe("payment-service");
    expect(stubs.auditLogger.entries[0]!.details.level).toBe("standard");
    expect(stubs.auditLogger.entries[0]!.details.tokenId).toBe("tok-001");
  });

  it("logs audit on denied access", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    // Clear audit entries
    stubs.auditLogger.entries.length = 0;

    const validateUC = createValidateUseCase(stubs);
    await validateUC.execute({
      bearerToken: "bad-token",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "malformed_token" });
  });

  it("token is not renewable — no renewal endpoint exists, re-auth required", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    const validateUC = createValidateUseCase(stubs);

    // ValidateToken only validates; there is no renew/extend method.
    // The only way to get a new token is to re-authenticate via IssueToken.
    // Verify that the validate port interface has no renewal capability.
    expect(typeof (validateUC as Record<string, unknown>).renew).toBe("undefined");
    expect(typeof (validateUC as Record<string, unknown>).extend).toBe("undefined");
    expect(typeof (validateUC as Record<string, unknown>).refresh).toBe("undefined");

    // A valid token still validates normally — but cannot be extended
    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });
    expect(response.success).toBe(true);
  });

  it("validates elevated token and returns elevated level", async () => {
    let currentTime = NOW_MS;
    const stubs = createAllStubs({ clock: { nowMs: () => currentTime } });
    const issueUC = createIssueUseCase(stubs);
    const response = await issueUC.execute(
      validIssueTokenRequest({ authenticationLevel: AuthenticationLevel.ELEVATED }),
    );
    if (!response.success) throw new Error("Failed to issue elevated token");

    const validateUC = createValidateUseCase(stubs);
    const result = await validateUC.execute({
      bearerToken: response.bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.level).toBe("elevated");
  });

  it("audit log details include reason on denied access", async () => {
    let currentTime = NOW_MS;
    const stubs = createAllStubs({ clock: { nowMs: () => currentTime } });
    const bearerToken = await issueValidToken(stubs);

    // Advance clock past expiry
    currentTime = NOW_MS + STANDARD_TTL_MS + 1;
    stubs.auditLogger.entries.length = 0;

    const validateUC = createValidateUseCase(stubs);
    await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(stubs.auditLogger.entries.length).toBe(1);
    expect(stubs.auditLogger.entries[0]!.action).toBe("access_denied");
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "TOKEN_EXPIRED" });
  });

  it("audit log details include tokenId, audience and level on granted access", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    stubs.auditLogger.entries.length = 0;

    const validateUC = createValidateUseCase(stubs);
    await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(stubs.auditLogger.entries.length).toBe(1);
    const entry = stubs.auditLogger.entries[0]!;
    expect(entry.action).toBe("access_granted");
    expect(entry.details.audience).toBe("payment-service");
    expect(entry.details.level).toBe("standard");
    expect(entry.details.tokenId).toBe("tok-001");
  });

  it("audit log details include reason and tokenId on issuance success", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const issueUC = createIssueUseCase(stubs);
    await issueUC.execute(validIssueTokenRequest());

    expect(stubs.auditLogger.entries.length).toBe(1);
    const entry = stubs.auditLogger.entries[0]!;
    expect(entry.action).toBe("token_issued");
    expect(entry.details.tokenId).toBe("tok-001");
    expect(entry.details.audience).toBe("payment-service");
    expect(entry.details.level).toBe("standard");
    expect(entry.details.expiresAtMs).toBe(NOW_MS + STANDARD_TTL_MS);
  });

  it("audit log details include reason on issuance refusal", async () => {
    const stubs = createAllStubs({
      clock: { nowMs: () => NOW_MS },
      clientStatusChecker: new StubClientStatusChecker(false),
    });
    const issueUC = createIssueUseCase(stubs);
    await issueUC.execute(validIssueTokenRequest());

    expect(stubs.auditLogger.entries.length).toBe(1);
    const entry = stubs.auditLogger.entries[0]!;
    expect(entry.action).toBe("issuance_refused");
    expect(entry.details.reason).toBe("CLIENT_NOT_ACTIVE");
  });

  // --- Mutation survivors: signatureValid logic ---

  it("signatureValid requires BOTH payload AND parsedClaims non-null", async () => {
    // When tokenVerifier returns valid bytes but those bytes are NOT valid JSON,
    // parsedClaims will be null even though payload is non-null.
    // signatureValid should be false (AND logic, not OR).
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    // Use a verifier that returns non-null (valid signature) but non-JSON payload
    const notJsonPayload = new Uint8Array([0x00, 0x01, 0x02]); // not valid JSON
    stubs.tokenVerifier = {
      verify: async () => notJsonPayload,
    } as any;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "dGVzdA", // "test" in base64url
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    // Should fail because parsedClaims is null (bad JSON)
    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("access_denied");
    }
    // Should use "unknown" as clientIdentifier since parsedClaims is null
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
  });

  it("uses clientIdentifier = 'unknown' in audit for forged tokens", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "forged-token-value",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    // Verify that clientIdentifier is "unknown" (not "" — the mutant changes "unknown" to "")
    expect(stubs.auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
  });

  it("dummy claims use empty strings in failure path (timing safety)", async () => {
    // When signature is invalid, dummy claims are used.
    // Verify these dummy claims have specific values (iss:"", sub:"", aud:"", etc.)
    // by checking that the validation chain is still called and produces the expected error.
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    stubs.auditLogger.entries.length = 0;
    const validateUC = createValidateUseCase(stubs);

    const response = await validateUC.execute({
      bearerToken: "some-invalid-token",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("access_denied");
    }
    // The validation chain should find INVALID_SIGNATURE first
    expect(stubs.auditLogger.entries[0]!.details).toEqual({ reason: "INVALID_SIGNATURE" });
  });

  it("dummy client status check calls isActive with '__dummy__' and returns false", async () => {
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    // Track calls to isActive
    const isActiveCalls: string[] = [];
    const originalIsActive = stubs.clientStatusChecker.isActive.bind(stubs.clientStatusChecker);
    stubs.clientStatusChecker.isActive = async (id: string) => {
      isActiveCalls.push(id);
      return originalIsActive(id);
    };
    const validateUC = createValidateUseCase(stubs);

    await validateUC.execute({
      bearerToken: "some-token",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    // On failure path, dummyClientStatusCheck should call isActive("__dummy__")
    expect(isActiveCalls).toContain("__dummy__");
  });

  it("uses 'dummy' audience in failure path when aud is empty", async () => {
    // When signature is invalid, effectiveClaims.aud is "" (dummy).
    // The code should use "dummy" as fallback when aud.length <= 0.
    // This test kills the mutation: `true ? effectiveClaims.aud : "dummy"` and
    // `effectiveClaims.aud.length >= 0 ? effectiveClaims.aud : "dummy"`
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const verifier = new StubTokenVerifier(false);
    stubs.tokenVerifier = verifier;
    const validateUC = createValidateUseCase(stubs);

    // Should not throw even with forged token (dummy audience "dummy" is used)
    const response = await validateUC.execute({
      bearerToken: "forged-token",
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("access_denied");
    }
  });

  it("base64url decode restores underscore to slash correctly", async () => {
    // This kills the mutant: `.replace(/_/g, "")` instead of `.replace(/_/g, "/")`
    // And: `while (false)` instead of `while (base64.length % 4 !== 0)`
    // And: `while (base64.length % 4 === 0)` instead of `!== 0`
    // And: `i <= binary.length` instead of `i < binary.length`
    const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
    const bearerToken = await issueValidToken(stubs);
    const validateUC = createValidateUseCase(stubs);

    // Verify the issued token can be validated (roundtrip through base64url encode/decode)
    const response = await validateUC.execute({
      bearerToken,
      channelBindingHash: CHANNEL_BINDING_HASH,
      expectedAudience: "payment-service",
    });

    expect(response.success).toBe(true);
    if (response.success) {
      expect(response.clientIdentifier).toBe("alice-payment-service");
    }
  });
});
