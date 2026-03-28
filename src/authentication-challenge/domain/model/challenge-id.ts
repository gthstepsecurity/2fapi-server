// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class ChallengeId {
  private constructor(readonly value: string) {}

  static fromString(value: string): ChallengeId {
    if (value.length === 0) {
      throw new Error("Challenge ID must not be empty");
    }
    return new ChallengeId(value);
  }

  equals(other: ChallengeId): boolean {
    return this.value === other.value;
  }
}
