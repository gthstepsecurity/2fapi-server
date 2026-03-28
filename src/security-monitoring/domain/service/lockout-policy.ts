// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { LockoutConfig } from "../model/lockout-config.js";
import type { FailedAttemptCounter } from "../model/failed-attempt-counter.js";

/**
 * Domain service implementing lockout decision logic.
 * Given a counter and config, determines if a client is locked out
 * and whether a new lockout should be triggered.
 */
export class LockoutPolicy {
  constructor(private readonly config: LockoutConfig) {}

  isLockedOut(counter: FailedAttemptCounter, nowMs: number): boolean {
    return counter.isLockedOut(nowMs, this.config);
  }

  shouldLockOut(counter: FailedAttemptCounter): boolean {
    return counter.consecutiveFailures >= this.config.threshold;
  }

  get lockoutConfig(): LockoutConfig {
    return this.config;
  }
}
