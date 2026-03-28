// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * E05: RNG health check wrapper for NAPI proof generation path.
 *
 * Validates that random bytes produced by the underlying source
 * have adequate entropy before they are used in proof generation.
 * Detects degraded RNG sources (stuck OSRng, VM snapshot, etc.)
 * by checking for low-entropy patterns.
 */
export interface RandomBytesSource {
  generateRandomBytes(length: number): Uint8Array;
}

export class ValidatedRandomnessProvider {
  constructor(private readonly source: RandomBytesSource) {}

  /**
   * Generates random bytes with entropy validation.
   * Rejects output that appears to come from a degraded RNG.
   *
   * @throws Error if the random output fails health checks
   */
  generateValidatedRandomBytes(length: number): Uint8Array {
    if (length <= 0) {
      throw new Error("Random byte length must be positive");
    }

    const bytes = this.source.generateRandomBytes(length);

    if (bytes.length !== length) {
      throw new Error(
        `RNG health check failed: requested ${length} bytes, got ${bytes.length}`,
      );
    }

    // Check for all-zero output (stuck RNG / uninitialized buffer)
    if (bytes.every((b) => b === 0)) {
      throw new Error("RNG health check failed: all-zero output detected");
    }

    // Check for constant-byte output (stuck RNG pattern)
    if (length >= 8 && bytes.every((b) => b === bytes[0])) {
      throw new Error("RNG health check failed: constant-byte output detected");
    }

    // Check for insufficient byte diversity on large outputs.
    // For 32+ bytes, we expect at least 8 distinct byte values.
    if (length >= 32) {
      const uniqueBytes = new Set(bytes);
      if (uniqueBytes.size < 8) {
        throw new Error(
          `RNG health check failed: insufficient diversity (${uniqueBytes.size} unique bytes in ${length} bytes)`,
        );
      }
    }

    return bytes;
  }
}
