// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export class ChannelBinding {
  private constructor(private readonly bytes: Uint8Array) {}

  /**
   * Creates a ChannelBinding from a TLS Exporter value.
   * Per RFC 9266, the exporter value must be 32 bytes (SHA-256)
   * or 48 bytes (SHA-384).
   */
  static fromTlsExporter(value: Uint8Array): ChannelBinding {
    if (value.length !== 32 && value.length !== 48) {
      throw new Error("Channel binding value must be 32 or 48 bytes (RFC 9266)");
    }
    return new ChannelBinding(new Uint8Array(value));
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /**
   * Constant-time comparison using XOR accumulator pattern.
   * Prevents timing side-channel attacks by always iterating over
   * all bytes regardless of where differences occur.
   * Length difference is folded into the accumulator (no early return).
   */
  equals(other: ChannelBinding): boolean {
    const maxLen = Math.max(this.bytes.length, other.bytes.length);
    let acc = this.bytes.length ^ other.bytes.length;
    for (let i = 0; i < maxLen; i++) {
      acc |= (this.bytes[i] ?? 0) ^ (other.bytes[i] ?? 0);
    }
    return acc === 0;
  }
}
