// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FailedAttemptCounter } from "../../model/failed-attempt-counter.js";

/**
 * Driven port for persisting failed attempt counters.
 * Each client has at most one counter.
 */
export interface AttemptCounterStore {
  findByClientIdentifier(clientIdentifier: string): Promise<FailedAttemptCounter | null>;
  save(counter: FailedAttemptCounter): Promise<void>;
  findAllLocked(): Promise<readonly FailedAttemptCounter[]>;
}
