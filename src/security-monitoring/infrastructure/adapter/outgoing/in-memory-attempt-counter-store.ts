// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AttemptCounterStore } from "../../../domain/port/outgoing/attempt-counter-store.js";
import { FailedAttemptCounter } from "../../../domain/model/failed-attempt-counter.js";

/**
 * In-memory reference implementation of AttemptCounterStore.
 * For testing and development only.
 */
export class InMemoryAttemptCounterStore implements AttemptCounterStore {
  private readonly counters = new Map<string, FailedAttemptCounter>();

  async findByClientIdentifier(clientIdentifier: string): Promise<FailedAttemptCounter | null> {
    return this.counters.get(clientIdentifier) ?? null;
  }

  async save(counter: FailedAttemptCounter): Promise<void> {
    this.counters.set(counter.clientIdentifier, counter);
  }

  async findAllLocked(): Promise<readonly FailedAttemptCounter[]> {
    return [...this.counters.values()].filter((c) => c.lockedOutAtMs !== null);
  }
}
