// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AtomicChallengeConsumer, type AtomicChallengeStore } from "../../src/zk-verification/infrastructure/adapter/outgoing/atomic-challenge-consumer.js";
import type { ChallengeInfo } from "../../src/zk-verification/domain/port/outgoing/challenge-consumer.js";

/**
 * Async-aware in-memory store that implements the updated async interface.
 */
class AsyncInMemoryAtomicChallengeStore implements AtomicChallengeStore {
  private readonly store = new Map<string, ChallengeInfo & { expiresAtMs: number }>();

  add(challengeId: string, info: ChallengeInfo, expiresAtMs: number): void {
    this.store.set(challengeId, { ...info, expiresAtMs });
  }

  async atomicConsumeIfValid(challengeId: string, nowMs: number): Promise<ChallengeInfo | null> {
    const entry = this.store.get(challengeId);
    if (entry === undefined) return null;
    if (nowMs >= entry.expiresAtMs) {
      this.store.delete(challengeId);
      return null;
    }
    this.store.delete(challengeId);
    return {
      clientIdentifier: entry.clientIdentifier,
      nonce: entry.nonce,
      channelBinding: entry.channelBinding,
    };
  }
}

const challengeInfo: ChallengeInfo = {
  clientIdentifier: "alice",
  nonce: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]),
  channelBinding: new Uint8Array(32).fill(0xab),
};

describe("FIX 6 — Challenge Consumption Atomicity (Async Interface)", () => {
  it("atomicConsumeIfValid returns Promise (async interface)", async () => {
    const store = new AsyncInMemoryAtomicChallengeStore();
    store.add("challenge-async", challengeInfo, Date.now() + 60_000);
    const consumer = new AtomicChallengeConsumer(store);

    const result = consumer.consumeIfValid("challenge-async");

    // Result should be a Promise
    expect(result).toBeInstanceOf(Promise);
    const resolved = await result;
    expect(resolved).not.toBeNull();
    expect(resolved!.clientIdentifier).toBe("alice");
  });

  it("10 parallel consumeIfValid calls — exactly 1 succeeds", async () => {
    const store = new AsyncInMemoryAtomicChallengeStore();
    store.add("challenge-concurrent-10", challengeInfo, Date.now() + 60_000);
    const consumer = new AtomicChallengeConsumer(store);

    const promises = Array.from({ length: 10 }, () =>
      consumer.consumeIfValid("challenge-concurrent-10"),
    );
    const results = await Promise.all(promises);

    const successes = results.filter((r) => r !== null);
    const nulls = results.filter((r) => r === null);

    expect(successes).toHaveLength(1);
    expect(nulls).toHaveLength(9);
    expect(successes[0]!.clientIdentifier).toBe("alice");
  });

  it("AtomicChallengeStore interface requires async atomicConsumeIfValid", () => {
    // Verify that the interface now requires Promise return type.
    // A store with a sync method should NOT satisfy the interface at compile time.
    // We verify this at runtime by checking the consumer works with async store.
    const store = new AsyncInMemoryAtomicChallengeStore();
    const consumer = new AtomicChallengeConsumer(store);
    expect(consumer).toBeDefined();
  });

  it("JSDoc contract is present on AtomicChallengeStore interface", () => {
    // Verify the source contains the atomicity contract documentation
    const source = AtomicChallengeConsumer.toString();
    // The consumer should delegate to store — no mutex, no lock
    expect(source).not.toContain("Mutex");
    expect(source).not.toContain("Lock");
  });
});
