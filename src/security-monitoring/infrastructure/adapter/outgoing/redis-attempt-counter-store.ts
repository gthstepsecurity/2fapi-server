// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AttemptCounterStore } from "../../../domain/port/outgoing/attempt-counter-store.js";
import { FailedAttemptCounter } from "../../../domain/model/failed-attempt-counter.js";

/**
 * Minimal Redis client interface for attempt counter operations.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
}

const KEY_PREFIX = "attempt:";

/**
 * Serialized counter shape stored as JSON in Redis.
 */
interface SerializedCounter {
  clientIdentifier: string;
  consecutiveFailures: number;
  lockedOutAtMs: number | null;
}

/**
 * Redis implementation of AttemptCounterStore.
 *
 * Stores failed attempt counters as JSON strings in Redis.
 * Uses atomic GET/SET operations. The counter is incremented
 * by the domain model (FailedAttemptCounter.increment) and then
 * saved back via this store.
 *
 * Locked counters are identified by scanning for keys where
 * the stored JSON has a non-null lockedOutAtMs field.
 */
export class RedisAttemptCounterStore implements AttemptCounterStore {
  constructor(private readonly redis: RedisClient) {}

  async findByClientIdentifier(clientIdentifier: string): Promise<FailedAttemptCounter | null> {
    const key = KEY_PREFIX + clientIdentifier;
    const raw = await this.redis.get(key);
    if (raw === null) {
      return null;
    }

    const data = JSON.parse(raw) as SerializedCounter;
    return FailedAttemptCounter.restore(
      data.clientIdentifier,
      data.consecutiveFailures,
      data.lockedOutAtMs,
    );
  }

  async save(counter: FailedAttemptCounter): Promise<void> {
    const key = KEY_PREFIX + counter.clientIdentifier;
    const serialized: SerializedCounter = {
      clientIdentifier: counter.clientIdentifier,
      consecutiveFailures: counter.consecutiveFailures,
      lockedOutAtMs: counter.lockedOutAtMs,
    };

    // If the counter is reset (0 failures, not locked), delete the key
    if (counter.consecutiveFailures === 0 && counter.lockedOutAtMs === null) {
      await this.redis.del(key);
      return;
    }

    await this.redis.set(key, JSON.stringify(serialized));
  }

  async findAllLocked(): Promise<readonly FailedAttemptCounter[]> {
    const keys = await this.redis.keys(KEY_PREFIX + "*");
    const locked: FailedAttemptCounter[] = [];

    for (const key of keys) {
      const raw = await this.redis.get(key);
      if (raw === null) continue;

      const data = JSON.parse(raw) as SerializedCounter;
      if (data.lockedOutAtMs !== null) {
        locked.push(
          FailedAttemptCounter.restore(
            data.clientIdentifier,
            data.consecutiveFailures,
            data.lockedOutAtMs,
          ),
        );
      }
    }

    return locked;
  }
}
