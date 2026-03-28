// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeConsumer, ChallengeInfo } from "../../../domain/port/outgoing/challenge-consumer.js";

/**
 * Contract for a store that provides database-level atomic
 * consume-and-return semantics (DELETE...RETURNING or compare-and-swap).
 *
 * The atomicity guarantee is provided by the store implementation,
 * NOT by an application-level mutex. This ensures correct behavior
 * under horizontal scaling with multiple server instances.
 *
 * **IMPLEMENTATION CONTRACT**: `atomicConsumeIfValid` MUST be
 * implemented as a single database-level atomic operation
 * (e.g., `DELETE ... RETURNING` in PostgreSQL, or an atomic
 * compare-and-swap in Redis). Application-level read-then-delete
 * patterns are NOT acceptable as they allow race conditions
 * under horizontal scaling.
 *
 * **WARNING**: In-memory implementations are suitable for testing
 * only. Production deployments MUST use a database-backed store
 * with true atomicity guarantees.
 */
export interface AtomicChallengeStore {
  /**
   * Atomically checks if the challenge exists and is not expired,
   * deletes it, and returns its info in a single operation.
   * Returns null if the challenge does not exist, was already consumed,
   * or has expired.
   *
   * This method MUST return a Promise to support async database operations.
   */
  atomicConsumeIfValid(challengeId: string, nowMs: number): Promise<ChallengeInfo | null>;
}

/**
 * ChallengeConsumer implementation that delegates atomicity to the
 * underlying store (database-level atomic operation).
 *
 * No application-level mutex, lock, or synchronized block is used.
 * The store's atomicConsumeIfValid method is the sole source of
 * atomicity, ensuring correctness under horizontal scaling.
 */
export class AtomicChallengeConsumer implements ChallengeConsumer {
  constructor(private readonly store: AtomicChallengeStore) {}

  async consumeIfValid(challengeId: string): Promise<ChallengeInfo | null> {
    const nowMs = Date.now();
    return this.store.atomicConsumeIfValid(challengeId, nowMs);
  }
}
