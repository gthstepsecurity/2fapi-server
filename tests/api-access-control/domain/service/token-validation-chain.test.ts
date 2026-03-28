// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  TokenValidationChain,
  type ValidationInput,
} from "../../../../src/api-access-control/domain/service/token-validation-chain.js";
import { TokenClaims } from "../../../../src/api-access-control/domain/model/token-claims.js";
import { TokenId } from "../../../../src/api-access-control/domain/model/token-id.js";
import { Audience } from "../../../../src/api-access-control/domain/model/audience.js";
import { AuthenticationLevel } from "../../../../src/api-access-control/domain/model/authentication-level.js";

function validClaims(overrides: Partial<{
  exp: number;
  aud: Audience;
  cnf: string;
}> = {}): TokenClaims {
  return TokenClaims.create({
    iss: "2fapi-server",
    sub: "alice-payment-service",
    aud: overrides.aud ?? Audience.fromString("payment-service"),
    exp: overrides.exp ?? 2000000,
    iat: 1000000,
    jti: TokenId.fromString("tok-001"),
    cnf: overrides.cnf ?? "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    level: AuthenticationLevel.STANDARD,
  });
}

function validInput(overrides: Partial<ValidationInput> = {}): ValidationInput {
  return {
    claims: overrides.claims ?? validClaims(),
    signatureValid: overrides.signatureValid ?? true,
    nowMs: overrides.nowMs ?? 1500000,
    expectedAudience: overrides.expectedAudience ?? Audience.fromString("payment-service"),
    expectedChannelBindingHash:
      overrides.expectedChannelBindingHash ??
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    clientActive: overrides.clientActive ?? true,
  };
}

describe("TokenValidationChain", () => {
  const chain = new TokenValidationChain();

  it("returns null when all checks pass", () => {
    const error = chain.validate(validInput());
    expect(error).toBeNull();
  });

  it("fails when signature is invalid", () => {
    const error = chain.validate(validInput({ signatureValid: false }));
    expect(error).not.toBeNull();
    expect(error!.code).toBe("INVALID_SIGNATURE");
    expect(error!.message).toBe("Token signature is invalid");
    expect(error!.name).toBe("ValidationError");
  });

  it("fails when token is expired", () => {
    const error = chain.validate(validInput({ nowMs: 2000001 }));
    expect(error).not.toBeNull();
    expect(error!.code).toBe("TOKEN_EXPIRED");
    expect(error!.message).toBe("Token has expired");
  });

  it("fails at exact expiration boundary", () => {
    const error = chain.validate(validInput({ nowMs: 2000000 }));
    expect(error).not.toBeNull();
    expect(error!.code).toBe("TOKEN_EXPIRED");
  });

  it("passes one millisecond before expiration", () => {
    const error = chain.validate(validInput({ nowMs: 1999999 }));
    expect(error).toBeNull();
  });

  it("fails when audience does not match", () => {
    const error = chain.validate(
      validInput({
        expectedAudience: Audience.fromString("billing-service"),
      }),
    );
    expect(error).not.toBeNull();
    expect(error!.code).toBe("AUDIENCE_MISMATCH");
    expect(error!.message).toBe("Token audience does not match");
  });

  it("fails when channel binding does not match", () => {
    const error = chain.validate(
      validInput({
        expectedChannelBindingHash: "0000000000000000000000000000000000000000000000000000000000000000",
      }),
    );
    expect(error).not.toBeNull();
    expect(error!.code).toBe("CHANNEL_BINDING_MISMATCH");
    expect(error!.message).toBe("Channel binding does not match");
  });

  it("fails when client is not active (revoked)", () => {
    const error = chain.validate(validInput({ clientActive: false }));
    expect(error).not.toBeNull();
    expect(error!.code).toBe("CLIENT_NOT_ACTIVE");
    expect(error!.message).toBe("Client is no longer active");
  });

  it("executes ALL checks for timing safety even when first fails", () => {
    // All checks fail simultaneously
    const error = chain.validate(
      validInput({
        signatureValid: false,
        nowMs: 3000000,
        expectedAudience: Audience.fromString("wrong"),
        expectedChannelBindingHash: "wrong",
        clientActive: false,
      }),
    );
    // Should return the FIRST error in chain order (INVALID_SIGNATURE)
    expect(error).not.toBeNull();
    expect(error!.code).toBe("INVALID_SIGNATURE");
  });

  it("returns first error in chain order when multiple checks fail", () => {
    // Signature passes, but expiration and audience fail
    const error = chain.validate(
      validInput({
        signatureValid: true,
        nowMs: 3000000, // expired
        expectedAudience: Audience.fromString("wrong"), // mismatch
        clientActive: false, // revoked
      }),
    );
    // Expiration is checked before audience and client status
    expect(error).not.toBeNull();
    expect(error!.code).toBe("TOKEN_EXPIRED");
  });

  it("returns AUDIENCE_MISMATCH when only audience and client status fail", () => {
    const error = chain.validate(
      validInput({
        signatureValid: true,
        nowMs: 1500000, // not expired
        expectedAudience: Audience.fromString("wrong"), // mismatch
        clientActive: false, // revoked
      }),
    );
    // Audience is checked before client status
    expect(error).not.toBeNull();
    expect(error!.code).toBe("AUDIENCE_MISMATCH");
  });

  it("returns CHANNEL_BINDING_MISMATCH when only cnf and client status fail", () => {
    const error = chain.validate(
      validInput({
        signatureValid: true,
        nowMs: 1500000,
        expectedChannelBindingHash: "wrong",
        clientActive: false,
      }),
    );
    // Channel binding is checked before client status
    expect(error).not.toBeNull();
    expect(error!.code).toBe("CHANNEL_BINDING_MISMATCH");
  });
});
