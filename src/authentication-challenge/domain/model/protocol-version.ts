// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class ProtocolVersion {
  private constructor(readonly value: string) {}

  static fromString(value: string): ProtocolVersion {
    if (value.length === 0) {
      throw new Error("Protocol version must not be empty");
    }
    return new ProtocolVersion(value);
  }

  equals(other: ProtocolVersion): boolean {
    return this.value === other.value;
  }
}
