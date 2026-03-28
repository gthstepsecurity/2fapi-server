// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Simple concurrency limiter for expensive operations like Argon2id hashing.
 * Prevents memory exhaustion by capping concurrent executions.
 */
export class ConcurrencyLimiter {
  private active = 0;

  constructor(private readonly maxConcurrent: number) {
    if (maxConcurrent <= 0) {
      throw new Error("maxConcurrent must be a positive integer");
    }
  }

  /** Attempts to acquire a slot. Returns true if granted, false if at capacity. */
  acquire(): boolean {
    if (this.active >= this.maxConcurrent) {
      return false;
    }
    this.active++;
    return true;
  }

  /** Releases a previously acquired slot. */
  release(): void {
    this.active = Math.max(0, this.active - 1);
  }

  /** Returns the number of currently active slots. */
  get activeCount(): number {
    return this.active;
  }
}
