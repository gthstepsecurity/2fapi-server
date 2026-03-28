// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryChallengeRepository } from "../../../../../src/authentication-challenge/infrastructure/adapter/outgoing/in-memory-challenge-repository.js";
import { Challenge } from "../../../../../src/authentication-challenge/domain/model/challenge.js";
import { ChallengeId } from "../../../../../src/authentication-challenge/domain/model/challenge-id.js";
import { Nonce } from "../../../../../src/authentication-challenge/domain/model/nonce.js";
import { ChannelBinding } from "../../../../../src/authentication-challenge/domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../../../../src/authentication-challenge/domain/model/challenge-expiry.js";
import { FirstFactorType } from "../../../../../src/authentication-challenge/domain/model/first-factor-type.js";

const TWO_MINUTES_MS = 2 * 60 * 1000;

function createChallenge(id: string, client: string, issuedAt: number): Challenge {
  return Challenge.issue(
    ChallengeId.fromString(id),
    client,
    Nonce.create(new Uint8Array(16).fill(0xab), BigInt(1)),
    ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xcc)),
    ChallengeExpiry.create(issuedAt, TWO_MINUTES_MS),
    FirstFactorType.ZKP,
  );
}

describe("InMemoryChallengeRepository", () => {
  it("should save and find a challenge by id", async () => {
    const repo = new InMemoryChallengeRepository();
    const challenge = createChallenge("ch-001", "alice", 1000000);

    await repo.save(challenge);

    const found = await repo.findById(ChallengeId.fromString("ch-001"));
    expect(found).not.toBeNull();
    expect(found!.id.equals(challenge.id)).toBe(true);
  });

  it("should return null for a nonexistent challenge id", async () => {
    const repo = new InMemoryChallengeRepository();

    const found = await repo.findById(ChallengeId.fromString("nonexistent"));

    expect(found).toBeNull();
  });

  it("should find pending challenge by client identifier", async () => {
    const repo = new InMemoryChallengeRepository();
    await repo.save(createChallenge("ch-001", "alice", 1000000));

    const found = await repo.findPendingByClientIdentifier("alice");

    expect(found).not.toBeNull();
    expect(found!.clientIdentifier).toBe("alice");
  });

  it("should not find invalidated challenge as pending", async () => {
    const repo = new InMemoryChallengeRepository();
    const challenge = createChallenge("ch-001", "alice", 1000000);
    await repo.save(challenge.invalidate());

    const found = await repo.findPendingByClientIdentifier("alice");

    expect(found).toBeNull();
  });

  it("should delete a challenge", async () => {
    const repo = new InMemoryChallengeRepository();
    await repo.save(createChallenge("ch-001", "alice", 1000000));

    await repo.delete(ChallengeId.fromString("ch-001"));

    const found = await repo.findById(ChallengeId.fromString("ch-001"));
    expect(found).toBeNull();
  });

  it("should delete expired challenges before a given time", async () => {
    const repo = new InMemoryChallengeRepository();
    await repo.save(createChallenge("ch-old", "alice", 1000000));
    await repo.save(createChallenge("ch-new", "bob", 1000000 + 5 * 60 * 1000));

    const purgeTime = 1000000 + 3 * 60 * 1000;
    const count = await repo.deleteExpiredBefore(purgeTime);

    expect(count).toBe(1);
    expect(await repo.findById(ChallengeId.fromString("ch-old"))).toBeNull();
    expect(await repo.findById(ChallengeId.fromString("ch-new"))).not.toBeNull();
  });

  it("should report capacity percentage", async () => {
    const repo = new InMemoryChallengeRepository(10);
    await repo.save(createChallenge("ch-001", "alice", 1000000));

    const capacity = await repo.capacityPercentage();

    expect(capacity).toBe(10);
  });

  it("should report 100% capacity when full", async () => {
    const repo = new InMemoryChallengeRepository(2);
    await repo.save(createChallenge("ch-001", "alice", 1000000));
    await repo.save(createChallenge("ch-002", "bob", 1000000));

    const capacity = await repo.capacityPercentage();

    expect(capacity).toBe(100);
  });
});
