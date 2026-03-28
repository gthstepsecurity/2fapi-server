// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeRepository } from "../../../domain/port/outgoing/challenge-repository.js";
import type { Challenge } from "../../../domain/model/challenge.js";
import type { ChallengeId } from "../../../domain/model/challenge-id.js";

export class InMemoryChallengeRepository implements ChallengeRepository {
  private readonly store = new Map<string, Challenge>();

  constructor(private readonly maxCapacity: number = 100_000) {}

  async save(challenge: Challenge): Promise<void> {
    this.store.set(challenge.id.value, challenge);
  }

  async findById(id: ChallengeId): Promise<Challenge | null> {
    return this.store.get(id.value) ?? null;
  }

  async findPendingByClientIdentifier(clientIdentifier: string): Promise<Challenge | null> {
    for (const challenge of this.store.values()) {
      if (challenge.clientIdentifier === clientIdentifier && challenge.status === "pending") {
        return challenge;
      }
    }
    return null;
  }

  async delete(id: ChallengeId): Promise<void> {
    this.store.delete(id.value);
  }

  async deleteExpiredBefore(nowMs: number): Promise<number> {
    let count = 0;
    for (const [key, challenge] of this.store.entries()) {
      if (!challenge.isValidAt(nowMs) && challenge.status !== "used") {
        this.store.delete(key);
        count++;
      }
    }
    return count;
  }

  async capacityPercentage(): Promise<number> {
    return Math.round((this.store.size / this.maxCapacity) * 100);
  }
}
