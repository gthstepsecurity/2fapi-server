// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const PROTOCOL_TAG = "2FApi-v1.0-Sigma";
const ENROLLMENT_TAG = "2FApi-v1.0-Enrollment";
const ROTATION_TAG = "2FApi-v1.0-Rotation";

export class DomainSeparationTag {
  private constructor(readonly value: string) {}

  /** Tag for authentication proof verification (Schnorr/Sigma protocol) */
  static protocol(): DomainSeparationTag {
    return new DomainSeparationTag(PROTOCOL_TAG);
  }

  /** Tag for enrollment proof-of-possession */
  static enrollment(): DomainSeparationTag {
    return new DomainSeparationTag(ENROLLMENT_TAG);
  }

  /** Tag for commitment rotation proof */
  static rotation(): DomainSeparationTag {
    return new DomainSeparationTag(ROTATION_TAG);
  }

  static fromString(value: string): DomainSeparationTag {
    if (value.length === 0) {
      throw new Error("Domain separation tag must not be empty");
    }
    return new DomainSeparationTag(value);
  }

  toBytes(): Uint8Array {
    return new TextEncoder().encode(this.value);
  }

  equals(other: DomainSeparationTag): boolean {
    return this.value === other.value;
  }
}
