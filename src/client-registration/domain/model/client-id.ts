// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const MIN_BYTE_LENGTH = 16;

export class ClientId {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = new Uint8Array(bytes);
  }

  static fromBytes(bytes: Uint8Array): ClientId {
    if (bytes.length < MIN_BYTE_LENGTH) {
      throw new Error(
        `ClientId must be at least 16 bytes, got ${bytes.length}`,
      );
    }
    return new ClientId(bytes);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  equals(other: ClientId): boolean {
    if (this.bytes.length !== other.bytes.length) return false;
    for (let i = 0; i < this.bytes.length; i++) {
      if (this.bytes[i] !== other.bytes[i]) return false;
    }
    return true;
  }

  toString(): string {
    return Array.from(this.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}
