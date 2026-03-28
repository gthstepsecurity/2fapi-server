// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object representing whether a client is currently locked out.
 * Does NOT disclose remaining duration (NIST AAL2 compliance).
 */
export class LockoutStatus {
  private constructor(
    readonly isLocked: boolean,
    readonly lockedOutAtMs: number | null,
  ) {}

  static unlocked(): LockoutStatus {
    return new LockoutStatus(false, null);
  }

  static locked(lockedOutAtMs: number): LockoutStatus {
    if (lockedOutAtMs < 0) {
      throw new Error("Lockout timestamp must be non-negative");
    }
    return new LockoutStatus(true, lockedOutAtMs);
  }
}
