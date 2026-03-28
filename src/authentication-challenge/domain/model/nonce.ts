// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const MINIMUM_RANDOM_BYTES = 16;

export class Nonce {
  private constructor(private readonly bytes: Uint8Array) {}

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /**
   * Constant-time comparison using XOR accumulator pattern.
   * Prevents timing side-channel attacks by always iterating over
   * all bytes regardless of where differences occur.
   *
   * Length mismatch is folded into the accumulator (not an early return)
   * to avoid leaking length information via timing.
   */
  equals(other: Nonce): boolean {
    const maxLen = Math.max(this.bytes.length, other.bytes.length);
    let acc = this.bytes.length ^ other.bytes.length; // non-zero if lengths differ
    for (let i = 0; i < maxLen; i++) {
      acc |= (this.bytes[i] ?? 0) ^ (other.bytes[i] ?? 0);
    }
    return acc === 0;
  }

  static create(randomPart: Uint8Array, counter: bigint): Nonce {
    if (counter < BigInt(0)) {
      throw new Error("Counter must be a non-negative integer");
    }
    if (randomPart.length < MINIMUM_RANDOM_BYTES) {
      throw new Error(
        `Random part must be at least ${MINIMUM_RANDOM_BYTES} bytes, got ${randomPart.length}`,
      );
    }
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, counter, false);
    const combined = new Uint8Array(randomPart.length + counterBytes.length);
    combined.set(randomPart, 0);
    combined.set(counterBytes, randomPart.length);
    return new Nonce(combined);
  }
}
