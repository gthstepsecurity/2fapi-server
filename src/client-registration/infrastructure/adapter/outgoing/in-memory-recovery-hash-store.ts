// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RecoveryHashStore } from "../../../domain/port/outgoing/recovery-hash-store.js";

/**
 * In-memory implementation of RecoveryHashStore.
 * Suitable for testing and development environments.
 */
export class InMemoryRecoveryHashStore implements RecoveryHashStore {
  private readonly hashes = new Map<string, Uint8Array>();
  private readonly failedAttempts = new Map<string, number>();

  async storeHash(clientIdentifier: string, hash: Uint8Array): Promise<void> {
    this.hashes.set(clientIdentifier, new Uint8Array(hash));
  }

  async getHash(clientIdentifier: string): Promise<Uint8Array | null> {
    const hash = this.hashes.get(clientIdentifier);
    return hash ? new Uint8Array(hash) : null;
  }

  async recordFailedAttempt(clientIdentifier: string): Promise<number> {
    const current = this.failedAttempts.get(clientIdentifier) ?? 0;
    const next = current + 1;
    this.failedAttempts.set(clientIdentifier, next);
    return next;
  }

  async resetAttempts(clientIdentifier: string): Promise<void> {
    this.failedAttempts.set(clientIdentifier, 0);
  }

  async getAttemptCount(clientIdentifier: string): Promise<number> {
    return this.failedAttempts.get(clientIdentifier) ?? 0;
  }

  async deleteHash(clientIdentifier: string): Promise<void> {
    this.hashes.delete(clientIdentifier);
    this.failedAttempts.delete(clientIdentifier);
  }
}
