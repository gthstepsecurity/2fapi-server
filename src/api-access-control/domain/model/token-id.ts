// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class TokenId {
  private constructor(readonly value: string) {}

  static fromString(value: string): TokenId {
    if (value.length === 0) {
      throw new Error("Token ID must not be empty");
    }
    return new TokenId(value);
  }

  equals(other: TokenId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
