// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const MAX_LENGTH = 256;

export class Audience {
  private constructor(readonly value: string) {}

  static fromString(value: string): Audience {
    if (value.length === 0) {
      throw new Error("Audience must not be empty");
    }
    if (value.length > MAX_LENGTH) {
      throw new Error("Audience must not exceed 256 characters");
    }
    return new Audience(value);
  }

  equals(other: Audience): boolean {
    return this.value === other.value;
  }
}
