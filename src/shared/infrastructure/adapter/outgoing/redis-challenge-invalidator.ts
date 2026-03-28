// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeInvalidator } from "../../../../client-registration/domain/port/outgoing/challenge-invalidator.js";

/**
 * Minimal Redis client interface for challenge invalidation.
 * Compatible with ioredis.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
}

const CLIENT_INDEX_PREFIX = "challenge:client:";
const CHALLENGE_KEY_PREFIX = "challenge:";

/**
 * Redis-backed challenge invalidator.
 *
 * Deletes all pending challenges for a client from Redis when the client
 * is revoked or their commitment is rotated. Uses the client index key
 * maintained by RedisChallengeRepository to find and delete the pending
 * challenge.
 */
export class RedisChallengeInvalidator implements ChallengeInvalidator {
  constructor(private readonly redis: RedisClient) {}

  async invalidateAllForClient(clientIdentifier: string): Promise<void> {
    try {
      // Look up the pending challenge ID from the client index
      const clientKey = CLIENT_INDEX_PREFIX + clientIdentifier;
      const challengeId = await this.redis.get(clientKey);

      if (challengeId !== null) {
        // Delete both the challenge and the client index atomically
        const challengeKey = CHALLENGE_KEY_PREFIX + challengeId;
        await this.redis.del(challengeKey, clientKey);
      }
    } catch {
      // Best-effort: challenges will expire via TTL regardless
    }
  }
}
