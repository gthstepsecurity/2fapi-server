// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeRepository } from "../../../domain/port/outgoing/challenge-repository.js";
import { Challenge } from "../../../domain/model/challenge.js";
import { ChallengeId } from "../../../domain/model/challenge-id.js";
import { Nonce } from "../../../domain/model/nonce.js";
import { ChannelBinding } from "../../../domain/model/channel-binding.js";
import { ChallengeExpiry } from "../../../domain/model/challenge-expiry.js";
import type { FirstFactorType } from "../../../domain/model/first-factor-type.js";

/**
 * Minimal Redis client interface.
 * Compatible with ioredis and node-redis after adapting.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: string[]): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  ttl(key: string): Promise<number>;
  dbsize(): Promise<number>;
}

/**
 * Serialized challenge shape stored in Redis as JSON.
 */
interface SerializedChallenge {
  id: string;
  clientIdentifier: string;
  nonce: string;          // hex-encoded bytes
  channelBinding: string; // hex-encoded bytes
  issuedAtMs: number;
  ttlMs: number;
  firstFactorType: string;
  status: string;
}

const KEY_PREFIX = "challenge:";
const CLIENT_INDEX_PREFIX = "challenge:client:";

/**
 * Redis implementation of ChallengeRepository.
 *
 * Leverages Redis TTL for automatic expiry of challenges.
 * Each challenge is stored as a JSON string with its Redis key TTL
 * set to the challenge's TTL (in seconds, rounded up).
 *
 * An additional index key maps client identifiers to their pending
 * challenge ID for fast lookups.
 */
export class RedisChallengeRepository implements ChallengeRepository {
  constructor(
    private readonly redis: RedisClient,
    private readonly maxCapacity: number = 100_000,
  ) {}

  async save(challenge: Challenge): Promise<void> {
    const key = KEY_PREFIX + challenge.id.value;
    const serialized = this.serialize(challenge);
    const ttlSeconds = Math.ceil(challenge.expiry.ttlMs / 1000);

    await this.redis.set(key, JSON.stringify(serialized), "EX", String(ttlSeconds));

    // Index for findPendingByClientIdentifier
    if (challenge.status === "pending") {
      const clientKey = CLIENT_INDEX_PREFIX + challenge.clientIdentifier;
      await this.redis.set(clientKey, challenge.id.value, "EX", String(ttlSeconds));
    }
  }

  async findById(id: ChallengeId): Promise<Challenge | null> {
    const key = KEY_PREFIX + id.value;
    const raw = await this.redis.get(key);
    if (raw === null) {
      return null;
    }

    const serialized = JSON.parse(raw) as SerializedChallenge;
    return this.deserialize(serialized);
  }

  async findPendingByClientIdentifier(clientIdentifier: string): Promise<Challenge | null> {
    const clientKey = CLIENT_INDEX_PREFIX + clientIdentifier;
    const challengeIdValue = await this.redis.get(clientKey);
    if (challengeIdValue === null) {
      return null;
    }

    const challengeId = ChallengeId.fromString(challengeIdValue);
    const challenge = await this.findById(challengeId);

    // Verify it's still pending (could have been updated)
    if (challenge !== null && challenge.status !== "pending") {
      return null;
    }

    return challenge;
  }

  async delete(id: ChallengeId): Promise<void> {
    // First retrieve to clean up the client index
    const challenge = await this.findById(id);
    if (challenge !== null) {
      const clientKey = CLIENT_INDEX_PREFIX + challenge.clientIdentifier;
      await this.redis.del(clientKey);
    }
    await this.redis.del(KEY_PREFIX + id.value);
  }

  async deleteExpiredBefore(_nowMs: number): Promise<number> {
    // Redis TTL handles expiry automatically.
    // This method scans for any remaining keys that should be expired
    // (e.g., status != "used" and past their TTL).
    // In practice, this is a no-op since Redis auto-expires.
    return 0;
  }

  async capacityPercentage(): Promise<number> {
    const size = await this.redis.dbsize();
    return Math.round((size / this.maxCapacity) * 100);
  }

  private serialize(challenge: Challenge): SerializedChallenge {
    return {
      id: challenge.id.value,
      clientIdentifier: challenge.clientIdentifier,
      nonce: Buffer.from(challenge.nonce.toBytes()).toString("hex"),
      channelBinding: Buffer.from(challenge.channelBinding.toBytes()).toString("hex"),
      issuedAtMs: challenge.expiry.issuedAtMs,
      ttlMs: challenge.expiry.ttlMs,
      firstFactorType: challenge.firstFactorType,
      status: challenge.status,
    };
  }

  private deserialize(data: SerializedChallenge): Challenge {
    const id = ChallengeId.fromString(data.id);

    const nonceBytes = Buffer.from(data.nonce, "hex");
    const COUNTER_SIZE = 8;
    const randomPart = new Uint8Array(nonceBytes.subarray(0, nonceBytes.length - COUNTER_SIZE));
    const counterView = new DataView(
      nonceBytes.buffer,
      nonceBytes.byteOffset + nonceBytes.length - COUNTER_SIZE,
      COUNTER_SIZE,
    );
    const counter = counterView.getBigUint64(0, false);
    const nonce = Nonce.create(randomPart, counter);

    const channelBinding = ChannelBinding.fromTlsExporter(
      new Uint8Array(Buffer.from(data.channelBinding, "hex")),
    );
    const expiry = ChallengeExpiry.create(data.issuedAtMs, data.ttlMs);
    const firstFactorType = data.firstFactorType as FirstFactorType;

    let challenge = Challenge.issue(id, data.clientIdentifier, nonce, channelBinding, expiry, firstFactorType);

    if (data.status === "used") {
      challenge = challenge.markUsed();
    } else if (data.status === "invalidated") {
      challenge = challenge.invalidate();
    }

    return challenge;
  }
}
