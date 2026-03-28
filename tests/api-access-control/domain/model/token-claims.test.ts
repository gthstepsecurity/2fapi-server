// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { TokenClaims } from "../../../../src/api-access-control/domain/model/token-claims.js";
import { TokenId } from "../../../../src/api-access-control/domain/model/token-id.js";
import { Audience } from "../../../../src/api-access-control/domain/model/audience.js";
import { AuthenticationLevel } from "../../../../src/api-access-control/domain/model/authentication-level.js";

function validClaims(overrides: Partial<{
  iss: string;
  sub: string;
  aud: Audience;
  exp: number;
  iat: number;
  jti: TokenId;
  cnf: string;
  level: AuthenticationLevel;
}> = {}): TokenClaims {
  return TokenClaims.create({
    iss: overrides.iss ?? "2fapi-server",
    sub: overrides.sub ?? "alice-payment-service",
    aud: overrides.aud ?? Audience.fromString("payment-service"),
    exp: overrides.exp ?? 2000000,
    iat: overrides.iat ?? 1000000,
    jti: overrides.jti ?? TokenId.fromString("tok-001"),
    cnf: overrides.cnf ?? "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    level: overrides.level ?? AuthenticationLevel.STANDARD,
  });
}

describe("TokenClaims", () => {
  it("creates with all required fields", () => {
    const claims = validClaims();
    expect(claims.iss).toBe("2fapi-server");
    expect(claims.sub).toBe("alice-payment-service");
    expect(claims.aud.value).toBe("payment-service");
    expect(claims.exp).toBe(2000000);
    expect(claims.iat).toBe(1000000);
    expect(claims.jti.value).toBe("tok-001");
    expect(claims.cnf).toBe("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    expect(claims.level).toBe("standard");
  });

  it("rejects empty issuer", () => {
    expect(() => validClaims({ iss: "" })).toThrow("Issuer must not be empty");
  });

  it("rejects empty subject", () => {
    expect(() => validClaims({ sub: "" })).toThrow("Subject must not be empty");
  });

  it("rejects expiration not after issuedAt", () => {
    expect(() => validClaims({ iat: 1000, exp: 1000 })).toThrow(
      "Expiration must be after issuedAt",
    );
  });

  it("rejects expiration before issuedAt", () => {
    expect(() => validClaims({ iat: 2000, exp: 1000 })).toThrow(
      "Expiration must be after issuedAt",
    );
  });

  it("rejects empty cnf hash", () => {
    expect(() => validClaims({ cnf: "" })).toThrow(
      "Channel binding hash must not be empty",
    );
  });

  it("isExpiredAt returns false when now is strictly before expiration", () => {
    const claims = validClaims({ exp: 2000000 });
    expect(claims.isExpiredAt(1999999)).toBe(false);
  });

  it("isExpiredAt returns true at exact expiration time", () => {
    const claims = validClaims({ exp: 2000000 });
    expect(claims.isExpiredAt(2000000)).toBe(true);
  });

  it("isExpiredAt returns true after expiration time", () => {
    const claims = validClaims({ exp: 2000000 });
    expect(claims.isExpiredAt(2000001)).toBe(true);
  });

  it("hasAudience matches the expected audience", () => {
    const claims = validClaims({ aud: Audience.fromString("payment-service") });
    expect(claims.hasAudience(Audience.fromString("payment-service"))).toBe(true);
  });

  it("hasAudience rejects a different audience", () => {
    const claims = validClaims({ aud: Audience.fromString("payment-service") });
    expect(claims.hasAudience(Audience.fromString("billing-service"))).toBe(false);
  });

  it("hasChannelBinding matches with constant-time comparison", () => {
    const hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const claims = validClaims({ cnf: hash });
    expect(claims.hasChannelBinding(hash)).toBe(true);
  });

  it("hasChannelBinding rejects different hash", () => {
    const claims = validClaims({
      cnf: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    });
    expect(
      claims.hasChannelBinding("1111110123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
    ).toBe(false);
  });

  it("hasChannelBinding rejects hash of different length", () => {
    const claims = validClaims({
      cnf: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    });
    expect(claims.hasChannelBinding("short")).toBe(false);
  });

  it("hasChannelBinding is constant-time even for different lengths (no early return on length)", () => {
    const cnf = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const claims = validClaims({ cnf });
    // Both must return false, but the implementation must not short-circuit on length.
    // We verify correctness here; timing is verified by code inspection.
    expect(claims.hasChannelBinding("short")).toBe(false);
    expect(claims.hasChannelBinding("x".repeat(128))).toBe(false);
    expect(claims.hasChannelBinding("")).toBe(false);
  });

  it("serialize produces canonical JSON for signing", () => {
    const claims = validClaims();
    const json = claims.serialize();
    const parsed = JSON.parse(json);
    expect(parsed.iss).toBe("2fapi-server");
    expect(parsed.sub).toBe("alice-payment-service");
    expect(parsed.aud).toBe("payment-service");
    expect(parsed.exp).toBe(2000000);
    expect(parsed.iat).toBe(1000000);
    expect(parsed.jti).toBe("tok-001");
    expect(parsed.cnf).toBe("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    expect(parsed.level).toBe("standard");
  });

  it("serialize key order is deterministic", () => {
    const claims = validClaims();
    const keys = Object.keys(JSON.parse(claims.serialize()));
    expect(keys).toEqual(["aud", "cnf", "exp", "iat", "iss", "jti", "level", "sub"]);
  });

  it("hasChannelBinding uses Math.max for iteration length (different-length strings)", () => {
    // Kill mutant: Math.min instead of Math.max
    // With Math.min, comparing "abc" (3 chars) to "abcdef" (6 chars) would
    // only iterate 3 chars and wrongly return true if prefix matches
    const claims = validClaims({
      cnf: "abc",
    });
    expect(claims.hasChannelBinding("abcdef")).toBe(false);
  });

  it("hasChannelBinding iterates beyond a.length for shorter a", () => {
    // Kill mutant: `i <= a.length ? a.charCodeAt(i) : 0` replaced by `true ? a.charCodeAt(i) : 0`
    // and `i <= a.length` replaced by `i < a.length`
    // With the mutant using `true`, accessing a.charCodeAt(i) when i >= a.length returns NaN
    // which would break the comparison. With `i <= a.length`, it reads one past the end.
    const claims = validClaims({
      cnf: "short",
    });
    // b is longer than a — the loop needs to handle indices beyond a.length
    expect(claims.hasChannelBinding("shortXX")).toBe(false);
  });

  it("hasChannelBinding iterates beyond b.length for shorter b", () => {
    // Kill mutant: `i <= b.length ? b.charCodeAt(i) : 0` replaced by `true ? b.charCodeAt(i) : 0`
    const longCnf = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const claims = validClaims({ cnf: longCnf });
    // b is shorter than a — the loop needs to handle indices beyond b.length
    expect(claims.hasChannelBinding("short")).toBe(false);
  });

  it("hasChannelBinding loop boundary: i < maxLen not i <= maxLen", () => {
    // Kill mutant: `for (let i = 0; i <= maxLen; i++)` — accesses out of bounds
    // Equal strings should still work correctly
    const hash = "test1234";
    const claims = validClaims({ cnf: hash });
    expect(claims.hasChannelBinding(hash)).toBe(true);
    expect(claims.hasChannelBinding("test1235")).toBe(false);
  });

  it("serialize produces valid JSON that roundtrips correctly", () => {
    const claims = validClaims();
    const json = claims.serialize();
    const parsed = JSON.parse(json);
    // Verify specific field types match
    expect(typeof parsed.aud).toBe("string");
    expect(typeof parsed.cnf).toBe("string");
    expect(typeof parsed.exp).toBe("number");
    expect(typeof parsed.iss).toBe("string");
    expect(typeof parsed.sub).toBe("string");
    expect(typeof parsed.jti).toBe("string");
    expect(typeof parsed.level).toBe("string");
  });
});
