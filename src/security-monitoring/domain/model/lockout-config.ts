// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object representing the lockout policy configuration.
 * Configurable threshold, duration, backoff multiplier, and max duration.
 * Immutable after creation.
 */
export class LockoutConfig {
  private constructor(
    readonly threshold: number,
    readonly durationMs: number,
    readonly backoffMultiplier: number,
    readonly maxDurationMs: number,
  ) {}

  static defaults(): LockoutConfig {
    const baseDuration = 60 * 60 * 1000;
    return new LockoutConfig(3, baseDuration, 1, baseDuration);
  }

  static create(
    threshold: number,
    durationMs: number,
    backoffMultiplier: number = 1,
    maxDurationMs: number = durationMs,
  ): LockoutConfig {
    if (!Number.isInteger(threshold)) {
      throw new Error("Threshold must be a positive integer");
    }
    if (threshold < 1) {
      throw new Error("Threshold must be at least 1");
    }
    if (durationMs <= 0) {
      throw new Error("Duration must be positive");
    }
    if (backoffMultiplier < 1) {
      throw new Error("Backoff multiplier must be at least 1");
    }
    if (maxDurationMs <= 0) {
      throw new Error("Max duration must be positive");
    }
    return new LockoutConfig(threshold, durationMs, backoffMultiplier, maxDurationMs);
  }

  /**
   * Computes the effective lockout duration for a given lockout count.
   * duration = min(baseDuration * multiplier^(lockoutCount-1), maxDuration)
   */
  effectiveDurationMs(lockoutCount: number): number {
    if (lockoutCount <= 0) return this.durationMs;
    const computed = this.durationMs * Math.pow(this.backoffMultiplier, lockoutCount - 1);
    return Math.min(computed, this.maxDurationMs);
  }
}
