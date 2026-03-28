// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CheckChallengeUseCase } from "../../../../src/authentication-challenge/application/usecase/check-challenge.usecase.js";
import { Challenge } from "../../../../src/authentication-challenge/domain/model/challenge.js";
import { ChallengeId } from "../../../../src/authentication-challenge/domain/model/challenge-id.js";
import { Nonce } from "../../../../src/authentication-challenge/domain/model/nonce.js";
import { ChannelBinding } from "../../../../src/authentication-challenge/domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../../../src/authentication-challenge/domain/model/challenge-expiry.js";
import { FirstFactorType } from "../../../../src/authentication-challenge/domain/model/first-factor-type.js";
import {
  createInMemoryChallengeRepository,
  createStubClock,
  createCapturingAuditLogger,
} from "../../../helpers/challenge-test-helpers.js";

const TWO_MINUTES_MS = 2 * 60 * 1000;

function createTestChallenge(issuedAtMs: number, id = "ch-001"): Challenge {
  return Challenge.issue(
    ChallengeId.fromString(id),
    "alice-payment-service",
    Nonce.create(new Uint8Array(16).fill(0xab), BigInt(1)),
    ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xcc)),
    ChallengeExpiry.create(issuedAtMs, TWO_MINUTES_MS),
    FirstFactorType.ZKP,
  );
}

describe("CheckChallengeUseCase", () => {
  it("should return valid when challenge is within validity window", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    const challenge = createTestChallenge(issuedAt);
    await repository.save(challenge);

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + 90_000),
      createCapturingAuditLogger(),
    );

    const result = await useCase.execute({ challengeId: "ch-001" });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.clientIdentifier).toBe("alice-payment-service");
      expect(result.nonce.length).toBeGreaterThanOrEqual(24);
    }
  });

  it("should return expired when challenge is at exact expiry boundary (strictly <)", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    await repository.save(createTestChallenge(issuedAt));

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + TWO_MINUTES_MS),
      createCapturingAuditLogger(),
    );

    const result = await useCase.execute({ challengeId: "ch-001" });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("expired");
    }
  });

  it("should return valid at 119 seconds (last valid second)", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    await repository.save(createTestChallenge(issuedAt));

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + 119_000),
      createCapturingAuditLogger(),
    );

    const result = await useCase.execute({ challengeId: "ch-001" });

    expect(result.valid).toBe(true);
  });

  it("should return unknown for a nonexistent challenge (indistinguishable from expired)", async () => {
    const repository = createInMemoryChallengeRepository();
    const auditLogger = createCapturingAuditLogger();

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(),
      auditLogger,
    );

    const result = await useCase.execute({ challengeId: "nonexistent_challenge" });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("expired");
    }
    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("challenge_expired");
    expect(auditLogger.entries[0]!.clientIdentifier).toBe("unknown");
    expect(auditLogger.entries[0]!.details).toEqual({
      challengeId: "nonexistent_challenge",
      reason: "not_found",
    });
  });

  it("should audit log expired challenge check with details", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    await repository.save(createTestChallenge(issuedAt));
    const auditLogger = createCapturingAuditLogger();

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + 3 * 60 * 1000),
      auditLogger,
    );

    await useCase.execute({ challengeId: "ch-001" });

    expect(auditLogger.entries).toHaveLength(1);
    expect(auditLogger.entries[0]!.action).toBe("challenge_expired");
    expect(auditLogger.entries[0]!.clientIdentifier).toBe("alice-payment-service");
    expect(auditLogger.entries[0]!.details).toEqual({
      challengeId: "ch-001",
      reason: "expired_or_invalidated",
    });
  });

  it("should return expired for a used challenge", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    const challenge = createTestChallenge(issuedAt);
    const used = challenge.markUsed();
    await repository.save(used);

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + 30_000),
      createCapturingAuditLogger(),
    );

    const result = await useCase.execute({ challengeId: "ch-001" });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("expired");
    }
  });

  it("should return expired for an invalidated challenge", async () => {
    const issuedAt = 1000000;
    const repository = createInMemoryChallengeRepository();
    const challenge = createTestChallenge(issuedAt);
    await repository.save(challenge.invalidate());

    const useCase = new CheckChallengeUseCase(
      repository,
      createStubClock(issuedAt + 30_000),
      auditLogger(),
    );

    const result = await useCase.execute({ challengeId: "ch-001" });

    expect(result.valid).toBe(false);
  });
});

function auditLogger() {
  return createCapturingAuditLogger();
}
