// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { LockoutConfig } from "./lockout-config.js";

/**
 * Value object tracking consecutive failed authentication attempts for a client.
 * Immutable — each operation returns a new instance.
 * Lockout is determined by checking threshold against the provided config.
 * Tracks lockoutCount for exponential backoff.
 */
export class FailedAttemptCounter {
  private constructor(
    readonly clientIdentifier: string,
    readonly consecutiveFailures: number,
    readonly lockedOutAtMs: number | null,
    readonly lockoutCount: number,
  ) {}

  static create(clientIdentifier: string): FailedAttemptCounter {
    return new FailedAttemptCounter(clientIdentifier, 0, null, 0);
  }

  static restore(
    clientIdentifier: string,
    consecutiveFailures: number,
    lockedOutAtMs: number | null,
    lockoutCount: number = 0,
  ): FailedAttemptCounter {
    return new FailedAttemptCounter(clientIdentifier, consecutiveFailures, lockedOutAtMs, lockoutCount);
  }

  /**
   * Returns a new counter with failures incremented.
   * Sets lockedOutAtMs when the threshold is reached (using config).
   * Increments lockoutCount on each new lockout trigger.
   */
  increment(nowMs: number, config: LockoutConfig): FailedAttemptCounter {
    const newCount = this.consecutiveFailures + 1;
    const reachesThreshold = newCount >= config.threshold;
    const lockoutTime = reachesThreshold ? nowMs : this.lockedOutAtMs;
    const newLockoutCount = reachesThreshold && (this.consecutiveFailures < config.threshold || this.lockedOutAtMs !== lockoutTime)
      ? (this.consecutiveFailures < config.threshold ? this.lockoutCount + 1 : this.lockoutCount)
      : this.lockoutCount;
    return new FailedAttemptCounter(this.clientIdentifier, newCount, lockoutTime, newLockoutCount);
  }

  /**
   * BE08: On success, decrement by 1 instead of full reset.
   * Prevents lockout evasion via success alternation (N-1 failures + 1 success pattern).
   */
  recordSuccess(): FailedAttemptCounter {
    const newCount = Math.max(0, this.consecutiveFailures - 1);
    const newLockedOutAt = newCount < 1 ? null : this.lockedOutAtMs;
    return new FailedAttemptCounter(this.clientIdentifier, newCount, newLockedOutAt, this.lockoutCount);
  }

  reset(): FailedAttemptCounter {
    return new FailedAttemptCounter(this.clientIdentifier, 0, null, this.lockoutCount);
  }

  isLockedOut(nowMs: number, config: LockoutConfig): boolean {
    if (this.consecutiveFailures < config.threshold) {
      return false;
    }
    if (this.lockedOutAtMs === null) {
      return false;
    }
    const effectiveDuration = config.effectiveDurationMs(this.lockoutCount);
    return nowMs <= this.lockedOutAtMs + effectiveDuration;
  }
}
