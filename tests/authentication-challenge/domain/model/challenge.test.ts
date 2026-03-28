// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Challenge } from "../../../../src/authentication-challenge/domain/model/challenge.js";
import { ChallengeId } from "../../../../src/authentication-challenge/domain/model/challenge-id.js";
import { Nonce } from "../../../../src/authentication-challenge/domain/model/nonce.js";
import { ChannelBinding } from "../../../../src/authentication-challenge/domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../../../src/authentication-challenge/domain/model/challenge-expiry.js";
import { FirstFactorType } from "../../../../src/authentication-challenge/domain/model/first-factor-type.js";

function createTestNonce(counter = BigInt(1)): Nonce {
  return Nonce.create(new Uint8Array(16).fill(0xab), counter);
}

function createTestBinding(): ChannelBinding {
  return ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xcc));
}

function createTestExpiry(issuedAt = 1000000): ChallengeExpiry {
  return ChallengeExpiry.create(issuedAt, 2 * 60 * 1000);
}

describe("Challenge", () => {
  it("should be created with all required components", () => {
    const id = ChallengeId.fromString("ch-001");
    const nonce = createTestNonce();
    const binding = createTestBinding();
    const expiry = createTestExpiry();
    const clientIdentifier = "alice-payment-service";

    const challenge = Challenge.issue(id, clientIdentifier, nonce, binding, expiry, FirstFactorType.ZKP);

    expect(challenge.id.equals(id)).toBe(true);
    expect(challenge.clientIdentifier).toBe(clientIdentifier);
    expect(challenge.status).toBe("pending");
    expect(challenge.firstFactorType).toBe(FirstFactorType.ZKP);
  });

  it("should start with pending status", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-002"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    expect(challenge.status).toBe("pending");
  });

  it("should be invalidated", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-003"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const invalidated = challenge.invalidate();

    expect(invalidated.status).toBe("invalidated");
  });

  it("should report valid when expiry is within window", () => {
    const issuedAt = 1000000;
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-004"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(issuedAt),
      FirstFactorType.ZKP,
    );

    expect(challenge.isValidAt(issuedAt + 90_000)).toBe(true);
  });

  it("should report invalid when expired", () => {
    const issuedAt = 1000000;
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-005"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(issuedAt),
      FirstFactorType.ZKP,
    );

    expect(challenge.isValidAt(issuedAt + 120_000)).toBe(false);
  });

  it("should report invalid when status is invalidated regardless of time", () => {
    const issuedAt = 1000000;
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-006"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(issuedAt),
      FirstFactorType.ZKP,
    );

    const invalidated = challenge.invalidate();

    expect(invalidated.isValidAt(issuedAt + 30_000)).toBe(false);
  });

  it("should mark challenge as used", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-007"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const used = challenge.markUsed();

    expect(used.status).toBe("used");
  });

  it("should not allow marking an invalidated challenge as used", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-008"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const invalidated = challenge.invalidate();

    expect(() => invalidated.markUsed()).toThrow("Cannot mark a non-pending challenge as used");
  });

  it("should not allow marking an already-used challenge as used again", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-011"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const used = challenge.markUsed();

    expect(() => used.markUsed()).toThrow("Cannot mark a non-pending challenge as used");
  });

  it("should not allow invalidating a used challenge", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-009"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const used = challenge.markUsed();

    expect(() => used.invalidate()).toThrow("Cannot invalidate a non-pending challenge");
  });

  it("should not allow invalidating an already invalidated challenge", () => {
    const challenge = Challenge.issue(
      ChallengeId.fromString("ch-010"),
      "alice",
      createTestNonce(),
      createTestBinding(),
      createTestExpiry(),
      FirstFactorType.ZKP,
    );

    const invalidated = challenge.invalidate();

    expect(() => invalidated.invalidate()).toThrow("Cannot invalidate a non-pending challenge");
  });
});
