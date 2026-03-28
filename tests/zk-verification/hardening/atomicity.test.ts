// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { AtomicChallengeConsumer } from "../../../src/zk-verification/infrastructure/adapter/outgoing/atomic-challenge-consumer.js";
import type { ChallengeInfo } from "../../../src/zk-verification/domain/port/outgoing/challenge-consumer.js";

/**
 * Simulates a database-level atomic store for challenges.
 * Uses a Map with atomic delete-and-return semantics:
 * the first caller to delete a key gets the value, subsequent
 * callers get null — mimicking DELETE...RETURNING in SQL.
 */
class InMemoryAtomicChallengeStore {
  private readonly store = new Map<string, ChallengeInfo & { expiresAtMs: number }>();

  add(challengeId: string, info: ChallengeInfo, expiresAtMs: number): void {
    this.store.set(challengeId, { ...info, expiresAtMs });
  }

  /**
   * Atomic delete-and-return: returns the challenge info if it exists
   * and is not expired, then removes it from the store in one operation.
   * Returns null if the challenge does not exist, was already consumed,
   * or has expired.
   */
  async atomicConsumeIfValid(challengeId: string, nowMs: number): Promise<ChallengeInfo | null> {
    const entry = this.store.get(challengeId);
    if (entry === undefined) {
      return null;
    }
    if (nowMs >= entry.expiresAtMs) {
      this.store.delete(challengeId);
      return null;
    }
    // Atomic: delete and return in one step
    this.store.delete(challengeId);
    return {
      clientIdentifier: entry.clientIdentifier,
      nonce: entry.nonce,
      channelBinding: entry.channelBinding,
    };
  }

  has(challengeId: string): boolean {
    return this.store.has(challengeId);
  }
}

describe("AtomicChallengeConsumer", () => {
  let store: InMemoryAtomicChallengeStore;
  let consumer: AtomicChallengeConsumer;

  const challengeInfo: ChallengeInfo = {
    clientIdentifier: "alice",
    nonce: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]),
    channelBinding: new Uint8Array(32).fill(0xab),
  };

  beforeEach(() => {
    store = new InMemoryAtomicChallengeStore();
    consumer = new AtomicChallengeConsumer(store);
  });

  it("consumes a valid challenge atomically and returns the challenge info", async () => {
    store.add("challenge-1", challengeInfo, Date.now() + 60_000);

    const result = await consumer.consumeIfValid("challenge-1");

    expect(result).not.toBeNull();
    expect(result!.clientIdentifier).toBe("alice");
    expect(result!.nonce).toEqual(challengeInfo.nonce);
    expect(result!.channelBinding).toEqual(challengeInfo.channelBinding);
    // Challenge is consumed — no longer in store
    expect(store.has("challenge-1")).toBe(false);
  });

  it("returns null when two concurrent consumeIfValid calls race — exactly one succeeds", async () => {
    store.add("challenge-concurrent", challengeInfo, Date.now() + 60_000);

    // Launch both concurrently
    const [result1, result2] = await Promise.all([
      consumer.consumeIfValid("challenge-concurrent"),
      consumer.consumeIfValid("challenge-concurrent"),
    ]);

    // Exactly one succeeds, the other gets null
    const successes = [result1, result2].filter((r) => r !== null);
    const nulls = [result1, result2].filter((r) => r === null);

    expect(successes).toHaveLength(1);
    expect(nulls).toHaveLength(1);
    expect(successes[0]!.clientIdentifier).toBe("alice");
  });

  it("returns null for already-consumed challenge", async () => {
    store.add("challenge-consumed", challengeInfo, Date.now() + 60_000);

    // First consumption succeeds
    const first = await consumer.consumeIfValid("challenge-consumed");
    expect(first).not.toBeNull();

    // Second attempt returns null
    const second = await consumer.consumeIfValid("challenge-consumed");
    expect(second).toBeNull();
  });

  it("returns null for non-existent challenge", async () => {
    const result = await consumer.consumeIfValid("does-not-exist");
    expect(result).toBeNull();
  });

  it("returns null for expired challenge", async () => {
    store.add("challenge-expired", challengeInfo, Date.now() - 1);

    const result = await consumer.consumeIfValid("challenge-expired");
    expect(result).toBeNull();
  });

  it("handles 50 concurrent requests — exactly 1 wins", async () => {
    store.add("challenge-high-concurrency", challengeInfo, Date.now() + 60_000);

    const promises = Array.from({ length: 50 }, () =>
      consumer.consumeIfValid("challenge-high-concurrency"),
    );
    const results = await Promise.all(promises);

    const successes = results.filter((r) => r !== null);
    const nulls = results.filter((r) => r === null);

    expect(successes).toHaveLength(1);
    expect(nulls).toHaveLength(49);
  });

  it("does not use application-level mutex — relies on store-level atomicity", () => {
    // Verify that the consumer delegates atomicity to the store,
    // not an in-process lock. The AtomicChallengeConsumer class
    // should NOT have any mutex, lock, or synchronized block.
    const consumerSource = AtomicChallengeConsumer.toString();
    expect(consumerSource).not.toContain("Mutex");
    expect(consumerSource).not.toContain("Lock");
    expect(consumerSource).not.toContain("synchronized");
  });

  it("returns indistinguishable errors for consumed and expired challenges", async () => {
    // Consumed challenge
    store.add("challenge-a", challengeInfo, Date.now() + 60_000);
    await consumer.consumeIfValid("challenge-a"); // consume it
    const consumedResult = await consumer.consumeIfValid("challenge-a");

    // Expired challenge
    store.add("challenge-b", challengeInfo, Date.now() - 1);
    const expiredResult = await consumer.consumeIfValid("challenge-b");

    // Non-existent challenge
    const unknownResult = await consumer.consumeIfValid("challenge-unknown");

    // All return null — indistinguishable
    expect(consumedResult).toBeNull();
    expect(expiredResult).toBeNull();
    expect(unknownResult).toBeNull();
  });
});
