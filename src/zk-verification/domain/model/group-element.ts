// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const ELEMENT_BYTE_LENGTH = 32;

/**
 * Raw bytes wrapper for a group element (Ristretto255 point).
 *
 * This class only validates byte length (must be exactly 32 bytes).
 * It does NOT validate canonical encoding of the underlying curve point.
 * Canonical validation is an infrastructure concern and must be performed
 * separately via the ElementValidator port before cryptographic operations.
 *
 * This separation is intentional: the domain model remains pure and free
 * of crypto library dependencies, while the infrastructure layer (via
 * ElementValidator) handles Ristretto255-specific canonical checks.
 */
export class GroupElement {
  private constructor(private readonly bytes: Uint8Array) {}

  static fromBytes(bytes: Uint8Array): GroupElement {
    if (bytes.length !== ELEMENT_BYTE_LENGTH) {
      throw new Error(`Group element must be exactly ${ELEMENT_BYTE_LENGTH} bytes, got ${bytes.length}`);
    }
    return new GroupElement(new Uint8Array(bytes));
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /** Checks if this is the identity (neutral) element of the group. */
  isIdentity(): boolean {
    let acc = 0;
    for (let i = 0; i < this.bytes.length; i++) {
      acc |= this.bytes[i]!;
    }
    return acc === 0;
  }

  /** Constant-time comparison using XOR accumulator. */
  equals(other: GroupElement): boolean {
    let acc = 0;
    for (let i = 0; i < ELEMENT_BYTE_LENGTH; i++) {
      acc |= this.bytes[i]! ^ other.bytes[i]!;
    }
    return acc === 0;
  }
}
