// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RedisAtomicChallengeStore } from "../../src/zk-verification/infrastructure/adapter/outgoing/redis-atomic-challenge-store.js";

/**
 * Sprint 17 — Finding 2 (HIGH): Redis Lua Script Client Index Key Bug
 *
 * The Lua script was passing CLIENT_INDEX_PREFIX + challengeId as KEYS[2]
 * instead of CLIENT_INDEX_PREFIX + clientIdentifier. This left orphan
 * client index entries after challenge consumption.
 */

function createSerializedChallenge(
  id: string,
  clientIdentifier: string,
  ttlMs: number = 60_000,
  issuedAtMs: number = Date.now(),
): string {
  return JSON.stringify({
    id,
    clientIdentifier,
    nonce: "aabbccdd",
    channelBinding: "11223344",
    issuedAtMs,
    ttlMs,
    status: "pending",
  });
}

describe("Redis Lua Script Client Index Key", () => {
  let store: RedisAtomicChallengeStore;
  let evalCalls: Array<{ keys: string[]; args: unknown[] }>;
  let deletedKeys: string[];
  let storedData: Map<string, string>;

  beforeEach(() => {
    evalCalls = [];
    deletedKeys = [];
    storedData = new Map();

    const fakeRedis = {
      get: async (key: string) => storedData.get(key) ?? null,
      del: async (...keys: string[]) => {
        keys.forEach((k) => deletedKeys.push(k));
        return keys.length;
      },
      eval: async (...args: unknown[]) => {
        const script = args[0] as string;
        const numKeys = args[1] as number;
        const keys: string[] = [];
        for (let i = 0; i < numKeys; i++) {
          keys.push(args[2 + i] as string);
        }
        const scriptArgs = args.slice(2 + numKeys);
        evalCalls.push({ keys, args: scriptArgs });

        // Simulate successful Lua execution: return the stored data
        const challengeKey = keys[0];
        const raw = storedData.get(challengeKey);
        if (!raw) return null;

        const data = JSON.parse(raw);
        if (data.status !== "pending") return null;

        const nowMs = scriptArgs[0] as number;
        if (nowMs >= data.issuedAtMs + data.ttlMs) return null;

        // Delete the keys the Lua script would delete
        storedData.delete(challengeKey);
        if (keys[1]) {
          storedData.delete(keys[1]);
          deletedKeys.push(keys[1]);
        }
        deletedKeys.push(challengeKey);

        return raw;
      },
    };

    store = new RedisAtomicChallengeStore(fakeRedis);
  });

  it("should pass CLIENT_INDEX_PREFIX + clientIdentifier as KEYS[2] to Lua", async () => {
    const challengeId = "ch-001";
    const clientIdentifier = "alice";
    const nowMs = Date.now();

    storedData.set(
      "challenge:" + challengeId,
      createSerializedChallenge(challengeId, clientIdentifier, 60_000, nowMs - 1000),
    );

    await store.atomicConsumeIfValid(challengeId, nowMs);

    // Verify the Lua eval was called with the correct KEYS[2]
    expect(evalCalls.length).toBe(1);
    expect(evalCalls[0].keys[0]).toBe("challenge:" + challengeId);
    // KEYS[2] must be the client index key using clientIdentifier, NOT challengeId
    expect(evalCalls[0].keys[1]).toBe("challenge:client:" + clientIdentifier);
  });

  it("should NOT pass challenge:client:<challengeId> as KEYS[2]", async () => {
    const challengeId = "ch-002";
    const clientIdentifier = "bob";
    const nowMs = Date.now();

    storedData.set(
      "challenge:" + challengeId,
      createSerializedChallenge(challengeId, clientIdentifier, 60_000, nowMs - 1000),
    );

    await store.atomicConsumeIfValid(challengeId, nowMs);

    expect(evalCalls.length).toBe(1);
    // It should NOT be challenge:client:ch-002 (the buggy value)
    expect(evalCalls[0].keys[1]).not.toBe("challenge:client:" + challengeId);
  });

  it("should delete both challenge key and client index key after consumption", async () => {
    const challengeId = "ch-003";
    const clientIdentifier = "carol";
    const nowMs = Date.now();

    storedData.set(
      "challenge:" + challengeId,
      createSerializedChallenge(challengeId, clientIdentifier, 60_000, nowMs - 1000),
    );
    storedData.set("challenge:client:" + clientIdentifier, challengeId);

    const result = await store.atomicConsumeIfValid(challengeId, nowMs);

    expect(result).not.toBeNull();
    expect(result!.clientIdentifier).toBe(clientIdentifier);
    // Both keys should have been targeted for deletion
    expect(deletedKeys).toContain("challenge:" + challengeId);
    expect(deletedKeys).toContain("challenge:client:" + clientIdentifier);
  });

  it("should return valid ChallengeInfo on successful consumption", async () => {
    const challengeId = "ch-004";
    const clientIdentifier = "dave";
    const nowMs = Date.now();

    storedData.set(
      "challenge:" + challengeId,
      createSerializedChallenge(challengeId, clientIdentifier, 60_000, nowMs - 1000),
    );

    const result = await store.atomicConsumeIfValid(challengeId, nowMs);

    expect(result).not.toBeNull();
    expect(result!.clientIdentifier).toBe(clientIdentifier);
    expect(result!.nonce).toBeInstanceOf(Uint8Array);
    expect(result!.channelBinding).toBeInstanceOf(Uint8Array);
  });
});
