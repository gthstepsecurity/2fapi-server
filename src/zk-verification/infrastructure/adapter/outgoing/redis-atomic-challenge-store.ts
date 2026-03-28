// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AtomicChallengeStore } from "./atomic-challenge-consumer.js";
import type { ChallengeInfo } from "../../../domain/port/outgoing/challenge-consumer.js";

/**
 * Minimal Redis client interface for atomic challenge operations.
 * Compatible with ioredis.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
}

const CHALLENGE_KEY_PREFIX = "challenge:";
const CLIENT_INDEX_PREFIX = "challenge:client:";

/**
 * Serialized challenge shape (same as RedisChallengeRepository).
 */
interface SerializedChallenge {
  id: string;
  clientIdentifier: string;
  nonce: string;          // hex-encoded bytes
  channelBinding: string; // hex-encoded bytes
  issuedAtMs: number;
  ttlMs: number;
  status: string;
}

/**
 * Redis implementation of AtomicChallengeStore.
 *
 * Provides atomic challenge consumption using GET followed by DEL.
 * The atomicity guarantee comes from Redis single-threaded execution model:
 * even though GET and DEL are separate commands, each Redis command is atomic,
 * and the challenge is validated + consumed in a best-effort atomic pattern.
 *
 * For true atomicity under concurrent access, this uses a Lua script
 * that atomically reads, validates, and deletes the challenge in a single
 * Redis operation.
 */
export class RedisAtomicChallengeStore implements AtomicChallengeStore {
  /**
   * Lua script for atomic GET-validate-DEL.
   * Returns the JSON string if found and not expired, nil otherwise.
   * Also cleans up the client index key using the clientIdentifier
   * extracted from the stored JSON data.
   *
   * KEYS[1] = challenge key (challenge:<challengeId>)
   * KEYS[2] = client index key (challenge:client:<clientIdentifier>)
   * ARGV[1] = current time in milliseconds
   */
  private static readonly CONSUME_SCRIPT = `
    local key = KEYS[1]
    local nowMs = tonumber(ARGV[1])
    local raw = redis.call('GET', key)
    if not raw then
      return nil
    end
    local data = cjson.decode(raw)
    if data.status ~= 'pending' then
      return nil
    end
    local expiresAtMs = data.issuedAtMs + data.ttlMs
    if nowMs >= expiresAtMs then
      redis.call('DEL', key)
      return nil
    end
    redis.call('DEL', key)
    local clientIndexKey = KEYS[2]
    redis.call('DEL', clientIndexKey)
    return raw
  `;

  constructor(private readonly redis: RedisClient & { eval: (...args: unknown[]) => Promise<unknown> }) {}

  async atomicConsumeIfValid(challengeId: string, nowMs: number): Promise<ChallengeInfo | null> {
    const key = CHALLENGE_KEY_PREFIX + challengeId;

    // First, read the challenge to extract the clientIdentifier for the correct KEYS[2]
    const preRead = await this.redis.get(key);
    if (preRead === null) {
      return null;
    }

    let clientIdentifier: string;
    try {
      const preData = JSON.parse(preRead) as SerializedChallenge;
      clientIdentifier = preData.clientIdentifier;
    } catch {
      return null;
    }

    const clientIndexKey = CLIENT_INDEX_PREFIX + clientIdentifier;

    try {
      // Execute Lua script with the correct client index key
      const raw = await this.redis.eval(
        RedisAtomicChallengeStore.CONSUME_SCRIPT,
        2,
        key,
        clientIndexKey,
        nowMs,
      );

      if (raw === null || raw === undefined) {
        return null;
      }

      const data = JSON.parse(raw as string) as SerializedChallenge;

      return {
        clientIdentifier: data.clientIdentifier,
        nonce: new Uint8Array(Buffer.from(data.nonce, "hex")),
        channelBinding: new Uint8Array(Buffer.from(data.channelBinding, "hex")),
      };
    } catch {
      // Fallback to non-atomic GET+DEL if Lua is not available
      return this.fallbackConsume(challengeId, nowMs);
    }
  }

  /**
   * Fallback implementation using GET + DEL (not fully atomic).
   * Used when the Redis instance does not support EVAL.
   */
  private async fallbackConsume(challengeId: string, nowMs: number): Promise<ChallengeInfo | null> {
    const key = CHALLENGE_KEY_PREFIX + challengeId;
    const raw = await this.redis.get(key);

    if (raw === null) {
      return null;
    }

    const data = JSON.parse(raw) as SerializedChallenge;

    if (data.status !== "pending") {
      return null;
    }

    const expiresAtMs = data.issuedAtMs + data.ttlMs;
    if (nowMs >= expiresAtMs) {
      await this.redis.del(key);
      return null;
    }

    // Delete the challenge (consume it)
    await this.redis.del(key);

    // Clean up client index
    const clientKey = CLIENT_INDEX_PREFIX + data.clientIdentifier;
    await this.redis.del(clientKey).catch(() => {});

    return {
      clientIdentifier: data.clientIdentifier,
      nonce: new Uint8Array(Buffer.from(data.nonce, "hex")),
      channelBinding: new Uint8Array(Buffer.from(data.channelBinding, "hex")),
    };
  }
}
