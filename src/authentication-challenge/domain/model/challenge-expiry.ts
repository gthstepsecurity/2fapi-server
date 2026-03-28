// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class ChallengeExpiry {
  private constructor(
    readonly issuedAtMs: number,
    readonly ttlMs: number,
  ) {}

  static create(issuedAtMs: number, ttlMs: number): ChallengeExpiry {
    if (ttlMs <= 0) {
      throw new Error("TTL must be positive");
    }
    return new ChallengeExpiry(issuedAtMs, ttlMs);
  }

  isValidAt(nowMs: number): boolean {
    return nowMs - this.issuedAtMs < this.ttlMs;
  }
}
