// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AccessToken } from "../../../../src/api-access-control/domain/model/access-token.js";
import { TokenClaims } from "../../../../src/api-access-control/domain/model/token-claims.js";
import { TokenId } from "../../../../src/api-access-control/domain/model/token-id.js";
import { Audience } from "../../../../src/api-access-control/domain/model/audience.js";
import { AuthenticationLevel } from "../../../../src/api-access-control/domain/model/authentication-level.js";

function validClaims(): TokenClaims {
  return TokenClaims.create({
    iss: "2fapi-server",
    sub: "alice-payment-service",
    aud: Audience.fromString("payment-service"),
    exp: 2000000,
    iat: 1000000,
    jti: TokenId.fromString("tok-001"),
    cnf: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    level: AuthenticationLevel.STANDARD,
  });
}

describe("AccessToken", () => {
  it("issues a token from claims and signed bytes", () => {
    const claims = validClaims();
    const signedBytes = new Uint8Array([1, 2, 3, 4]);
    const token = AccessToken.issue(claims, signedBytes);

    expect(token.claims).toBe(claims);
    expect(token.signedBytes).toEqual(signedBytes);
  });

  it("returns a defensive copy of signedBytes", () => {
    const claims = validClaims();
    const original = new Uint8Array([1, 2, 3]);
    const token = AccessToken.issue(claims, original);

    const returned = token.signedBytes;
    returned[0] = 0xff;
    expect(token.signedBytes[0]).toBe(1);
  });

  it("toBearer returns base64url-encoded signed bytes", () => {
    const claims = validClaims();
    const signedBytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const token = AccessToken.issue(claims, signedBytes);

    const bearer = token.toBearer();
    // Verify it's a non-empty string
    expect(bearer.length).toBeGreaterThan(0);
    // Verify base64url characters only (no +, /, =)
    expect(bearer).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("does not expose signedBytes to external mutation via constructor", () => {
    const claims = validClaims();
    const original = new Uint8Array([1, 2, 3]);
    const token = AccessToken.issue(claims, original);

    // Mutate the original array after construction
    original[0] = 0xff;
    expect(token.signedBytes[0]).toBe(1);
  });

  it("toBearer correctly encodes '+' as '-' in base64url", () => {
    const claims = validClaims();
    // 0xFB produces '+' in standard base64
    const signedBytes = new Uint8Array([0xfb, 0xef, 0xbe]);
    const token = AccessToken.issue(claims, signedBytes);
    const bearer = token.toBearer();

    // Should use '-' instead of '+'
    expect(bearer).not.toContain("+");
    expect(bearer).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("toBearer correctly encodes '/' as '_' in base64url", () => {
    const claims = validClaims();
    // 0xFF, 0xFF produces '/' in standard base64
    const signedBytes = new Uint8Array([0xff, 0xff, 0xff]);
    const token = AccessToken.issue(claims, signedBytes);
    const bearer = token.toBearer();

    // Should use '_' instead of '/'
    expect(bearer).not.toContain("/");
    expect(bearer).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("toBearer strips all trailing '=' padding characters", () => {
    const claims = validClaims();
    // A 1-byte input produces "XX==" in base64 (2 padding chars)
    const signedBytes = new Uint8Array([0xab]);
    const token = AccessToken.issue(claims, signedBytes);
    const bearer = token.toBearer();

    expect(bearer).not.toContain("=");
    // Verify the bearer can be decoded back
    expect(bearer.length).toBeGreaterThan(0);
  });

  it("toBearer roundtrips correctly with validate-token decode", () => {
    const claims = validClaims();
    // Use bytes that will produce +, /, and = in standard base64
    const signedBytes = new Uint8Array([0xfb, 0xef, 0xbe, 0xff, 0xff]);
    const token = AccessToken.issue(claims, signedBytes);
    const bearer = token.toBearer();

    // Manually decode base64url to verify correctness
    let base64 = bearer.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
      base64 += "=";
    }
    const binary = atob(base64);
    const decoded = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      decoded[i] = binary.charCodeAt(i);
    }
    expect(decoded).toEqual(signedBytes);
  });
});
