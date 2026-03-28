// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const SCALAR_BYTE_LENGTH = 32;

export class ScalarValue {
  private constructor(private readonly bytes: Uint8Array) {}

  static fromBytes(bytes: Uint8Array): ScalarValue {
    if (bytes.length !== SCALAR_BYTE_LENGTH) {
      throw new Error(`Scalar must be exactly ${SCALAR_BYTE_LENGTH} bytes, got ${bytes.length}`);
    }
    return new ScalarValue(new Uint8Array(bytes));
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  isZero(): boolean {
    let acc = 0;
    for (let i = 0; i < this.bytes.length; i++) {
      acc |= this.bytes[i]!;
    }
    return acc === 0;
  }

  /** Constant-time comparison using XOR accumulator. */
  equals(other: ScalarValue): boolean {
    let acc = 0;
    for (let i = 0; i < SCALAR_BYTE_LENGTH; i++) {
      acc |= this.bytes[i]! ^ other.bytes[i]!;
    }
    return acc === 0;
  }
}
