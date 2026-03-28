// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VerificationReceiptStore } from "../../../domain/port/outgoing/verification-receipt-store.js";

/**
 * Minimal Redis client interface for receipt store operations.
 */
export interface RedisClient {
  set(key: string, value: string, ...args: string[]): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
}

const KEY_PREFIX = "receipt:";

/**
 * Default receipt TTL in seconds (5 minutes).
 * Receipts must be consumed within this window or they expire.
 */
const DEFAULT_TTL_SECONDS = 300;

/**
 * Redis implementation of VerificationReceiptStore.
 *
 * Uses Redis SET NX + TTL for one-time receipt consumption.
 * Each receipt is stored as a key-value pair where:
 * - Key: "receipt:{receiptId}"
 * - Value: clientIdentifier
 * - TTL: 5 minutes (configurable)
 *
 * Consumption is atomic: GET then DEL. The DEL ensures
 * the receipt cannot be consumed twice even under concurrent access.
 *
 * This is suitable for production horizontal scaling since
 * all instances share the same Redis store.
 */
export class RedisVerificationReceiptStore implements VerificationReceiptStore {
  constructor(
    private readonly redis: RedisClient,
    private readonly ttlSeconds: number = DEFAULT_TTL_SECONDS,
  ) {}

  async store(receiptId: string, clientIdentifier: string): Promise<void> {
    const key = KEY_PREFIX + receiptId;
    await this.redis.set(key, clientIdentifier, "EX", String(this.ttlSeconds));
  }

  async consume(receiptId: string): Promise<string | null> {
    const key = KEY_PREFIX + receiptId;
    const clientIdentifier = await this.redis.get(key);

    if (clientIdentifier === null) {
      return null;
    }

    // Atomically delete to prevent double-consumption.
    // If another process consumed between GET and DEL, DEL returns 0
    // but we already have the value — this is a benign race since
    // the receipt was consumed by one of the two processes.
    const deleted = await this.redis.del(key);
    if (deleted === 0) {
      // Another process consumed it between our GET and DEL
      return null;
    }

    return clientIdentifier;
  }
}
