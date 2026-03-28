// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object for protocol version negotiation.
 * Ensures WASM module and server agree on transcript format.
 */
export class ProtocolVersion {
  private constructor(
    readonly major: number,
    readonly minor: number,
  ) {}

  static readonly CURRENT = new ProtocolVersion(1, 0);

  static parse(version: string): ProtocolVersion | null {
    const match = version.match(/^(\d+)\.(\d+)$/);
    if (!match) return null;
    const major = parseInt(match[1]!, 10);
    if (major === 0) return null; // R1-12: reject version 0
    return new ProtocolVersion(major, parseInt(match[2]!, 10));
  }

  isCompatibleWith(other: ProtocolVersion): boolean {
    return this.major === other.major;
  }

  toString(): string {
    return `${this.major}.${this.minor}`;
  }
}
