// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { IssueTokenUseCase } from "../../src/api-access-control/application/usecase/issue-token.usecase.js";
import { ValidateTokenUseCase } from "../../src/api-access-control/application/usecase/validate-token.usecase.js";
import { TokenIssuancePolicy } from "../../src/api-access-control/domain/service/token-issuance-policy.js";
import { TokenValidationChain } from "../../src/api-access-control/domain/service/token-validation-chain.js";
import { AuthenticationLevel, STANDARD_TTL_MS, ELEVATED_TTL_MS } from "../../src/api-access-control/domain/model/authentication-level.js";
import { TokenIssued } from "../../src/api-access-control/domain/event/token-issued.js";
import {
  createAllStubs,
  createPreloadedReceiptStore,
  validIssueTokenRequest,
  StubClientStatusChecker,
  StubAuthorizationChecker,
  StubTokenVerifier,
  ISSUER,
  CHANNEL_BINDING_HASH,
} from "../helpers/access-control-test-helpers.js";

const NOW_MS = 1_700_000_000_000; // realistic epoch ms

function createService(overrides: {
  clientActive?: boolean;
  clientAuthorized?: boolean;
  nowMs?: number;
} = {}) {
  let currentTime = overrides.nowMs ?? NOW_MS;
  const clientStatusChecker = new StubClientStatusChecker(overrides.clientActive ?? true);
  const authorizationChecker = new StubAuthorizationChecker(overrides.clientAuthorized ?? true);
  const stubs = createAllStubs({
    clock: { nowMs: () => currentTime },
    clientStatusChecker,
    authorizationChecker,
  });

  const issuancePolicy = new TokenIssuancePolicy();
  const validationChain = new TokenValidationChain();

  const issueToken = new IssueTokenUseCase(
    stubs.clientStatusChecker,
    stubs.authorizationChecker,
    stubs.tokenSigner,
    stubs.auditLogger,
    stubs.eventPublisher,
    stubs.clock,
    stubs.idGenerator,
    issuancePolicy,
    ISSUER,
    stubs.receiptStore,
  );

  const validateToken = new ValidateTokenUseCase(
    stubs.tokenVerifier,
    stubs.clientStatusChecker,
    stubs.auditLogger,
    stubs.clock,
    validationChain,
  );

  return {
    issueToken,
    validateToken,
    stubs,
    clientStatusChecker,
    setTime: (ms: number) => { currentTime = ms; },
  };
}

describe("API Access Control — Acceptance Tests", () => {
  describe("End-to-end: issue + validate", () => {
    it("issues a token then validates it successfully", async () => {
      const { issueToken, validateToken } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: CHANNEL_BINDING_HASH,
        expectedAudience: "payment-service",
      });

      expect(validateResponse.success).toBe(true);
      if (!validateResponse.success) return;
      expect(validateResponse.clientIdentifier).toBe("alice-payment-service");
      expect(validateResponse.audience).toBe("payment-service");
      expect(validateResponse.level).toBe("standard");
    });

    it("issues elevated token then validates with correct TTL", async () => {
      const { issueToken, validateToken } = createService();

      const issueResponse = await issueToken.execute(
        validIssueTokenRequest({
          authenticationLevel: AuthenticationLevel.ELEVATED,
        }),
      );
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;
      expect(issueResponse.expiresAtMs).toBe(NOW_MS + ELEVATED_TTL_MS);

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: CHANNEL_BINDING_HASH,
        expectedAudience: "payment-service",
      });

      expect(validateResponse.success).toBe(true);
      if (!validateResponse.success) return;
      expect(validateResponse.level).toBe("elevated");
    });

    it("token expires after TTL", async () => {
      const { issueToken, validateToken, setTime } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;

      // Advance past TTL
      setTime(NOW_MS + STANDARD_TTL_MS + 1);

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: CHANNEL_BINDING_HASH,
        expectedAudience: "payment-service",
      });

      expect(validateResponse.success).toBe(false);
      if (validateResponse.success) return;
      expect(validateResponse.error).toBe("access_denied");
    });
  });

  describe("Token issuance failures", () => {
    it("refuses when client is revoked", async () => {
      const { issueToken } = createService({ clientActive: false });

      const response = await issueToken.execute(validIssueTokenRequest());
      expect(response.success).toBe(false);
      if (response.success) return;
      expect(response.error).toBe("issuance_refused");
    });

    it("refuses when client is not authorized for audience", async () => {
      const { issueToken } = createService({ clientAuthorized: false });

      const response = await issueToken.execute(validIssueTokenRequest());
      expect(response.success).toBe(false);
      if (response.success) return;
      expect(response.error).toBe("issuance_refused");
    });
  });

  describe("Token validation failures", () => {
    it("denies access when audience does not match", async () => {
      const { issueToken, validateToken } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: CHANNEL_BINDING_HASH,
        expectedAudience: "billing-service", // wrong audience
      });

      expect(validateResponse.success).toBe(false);
      if (validateResponse.success) return;
      expect(validateResponse.error).toBe("access_denied");
    });

    it("denies access when channel binding does not match", async () => {
      const { issueToken, validateToken } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: "0000000000000000000000000000000000000000000000000000000000000000",
        expectedAudience: "payment-service",
      });

      expect(validateResponse.success).toBe(false);
      if (validateResponse.success) return;
      expect(validateResponse.error).toBe("access_denied");
    });

    it("denies access when client gets revoked between issuance and validation", async () => {
      const { issueToken, validateToken, clientStatusChecker } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);
      if (!issueResponse.success) return;

      // Revoke client
      clientStatusChecker.setActive(false);

      const validateResponse = await validateToken.execute({
        bearerToken: issueResponse.bearerToken,
        channelBindingHash: CHANNEL_BINDING_HASH,
        expectedAudience: "payment-service",
      });

      expect(validateResponse.success).toBe(false);
      if (validateResponse.success) return;
      expect(validateResponse.error).toBe("access_denied");
    });

    it("all error responses are indistinguishable (same error code)", async () => {
      const { issueToken, validateToken, clientStatusChecker, setTime, stubs } = createService();

      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      if (!issueResponse.success) throw new Error("Setup failed");

      // Test different failure modes
      const failures: Array<{ bearerToken: string; cnf: string; aud: string; setup: () => void }> = [
        {
          bearerToken: issueResponse.bearerToken,
          cnf: CHANNEL_BINDING_HASH,
          aud: "payment-service",
          setup: () => { setTime(NOW_MS + STANDARD_TTL_MS + 1); }, // expired
        },
        {
          bearerToken: issueResponse.bearerToken,
          cnf: CHANNEL_BINDING_HASH,
          aud: "wrong-audience",
          setup: () => { setTime(NOW_MS); }, // reset time
        },
        {
          bearerToken: issueResponse.bearerToken,
          cnf: "0000000000000000",
          aud: "payment-service",
          setup: () => {},
        },
        {
          bearerToken: "totally-forged-token",
          cnf: CHANNEL_BINDING_HASH,
          aud: "payment-service",
          setup: () => {},
        },
      ];

      for (const f of failures) {
        f.setup();
        const response = await validateToken.execute({
          bearerToken: f.bearerToken,
          channelBindingHash: f.cnf,
          expectedAudience: f.aud,
        });
        expect(response.success).toBe(false);
        if (!response.success) {
          expect(response.error).toBe("access_denied");
        }
      }
    });
  });

  describe("Audit trail", () => {
    it("produces audit entries for the complete flow", async () => {
      const { issueToken, validateToken, stubs } = createService();

      // Issue
      const issueResponse = await issueToken.execute(validIssueTokenRequest());
      expect(issueResponse.success).toBe(true);

      // Validate
      if (issueResponse.success) {
        await validateToken.execute({
          bearerToken: issueResponse.bearerToken,
          channelBindingHash: CHANNEL_BINDING_HASH,
          expectedAudience: "payment-service",
        });
      }

      // Verify we have at least issuance + validation audit entries
      const actions = stubs.auditLogger.entries.map((e) => e.action);
      expect(actions).toContain("token_issued");
      expect(actions).toContain("access_granted");
    });
  });

  describe("Events", () => {
    it("publishes TokenIssued event with correct data", async () => {
      const { issueToken, stubs } = createService();

      await issueToken.execute(validIssueTokenRequest());

      expect(stubs.eventPublisher.events.length).toBe(1);
      const event = stubs.eventPublisher.events[0] as TokenIssued;
      expect(event.eventType).toBe("TokenIssued");
      expect(event.clientIdentifier).toBe("alice-payment-service");
      expect(event.audience).toBe("payment-service");
      expect(event.authenticationLevel).toBe("standard");
      expect(event.issuedAtMs).toBe(NOW_MS);
    });
  });
});
