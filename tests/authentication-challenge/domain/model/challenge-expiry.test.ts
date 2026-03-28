// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChallengeExpiry } from "../../../../src/authentication-challenge/domain/model/challenge-expiry.js";

describe("ChallengeExpiry", () => {
  const TWO_MINUTES_MS = 2 * 60 * 1000;

  it("should be created with an issuance time and TTL", () => {
    const issuedAt = 1000000;
    const expiry = ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS);

    expect(expiry.issuedAtMs).toBe(issuedAt);
    expect(expiry.ttlMs).toBe(TWO_MINUTES_MS);
  });

  it("should report valid when elapsed time is strictly less than TTL", () => {
    const issuedAt = 1000000;
    const expiry = ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS);

    // 90 seconds later
    const now = issuedAt + 90 * 1000;
    expect(expiry.isValidAt(now)).toBe(true);
  });

  it("should report expired when elapsed time equals TTL exactly (strictly less than)", () => {
    const issuedAt = 1000000;
    const expiry = ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS);

    // exactly 120 seconds later
    const now = issuedAt + TWO_MINUTES_MS;
    expect(expiry.isValidAt(now)).toBe(false);
  });

  it("should report expired when elapsed time exceeds TTL", () => {
    const issuedAt = 1000000;
    const expiry = ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS);

    // 3 minutes later
    const now = issuedAt + 3 * 60 * 1000;
    expect(expiry.isValidAt(now)).toBe(false);
  });

  it("should report valid at 119 seconds (last valid second)", () => {
    const issuedAt = 1000000;
    const expiry = ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS);

    const now = issuedAt + 119 * 1000;
    expect(expiry.isValidAt(now)).toBe(true);
  });

  it("should reject non-positive TTL", () => {
    expect(() => ChallengeExpiry.create(1000, 0)).toThrow("TTL must be positive");
  });
});
