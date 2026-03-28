// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Validates that random byte output from the OS RNG is healthy
 * before using it in cryptographic operations.
 *
 * Checks:
 * 1. Not all-zeros (catastrophic RNG failure)
 * 2. Sufficient entropy: at least 16 distinct byte values in 32 bytes
 *    (~128 bits minimum entropy, catches stuck/repeated/low-quality patterns)
 */

export interface RngHealthResult {
  readonly healthy: boolean;
  readonly error?: "rng_health_failure" | "rng_low_entropy";
}

const MIN_DISTINCT_BYTE_VALUES = 16;

export class RngHealthChecker {
  /**
   * Validates the entropy quality of random bytes.
   * @param randomBytes Raw bytes from the OS RNG (expected 32 bytes)
   */
  validate(randomBytes: Uint8Array): RngHealthResult {
    // Check for all-zeros (catastrophic failure)
    if (this.isAllSameByte(randomBytes, 0x00)) {
      return { healthy: false, error: "rng_health_failure" };
    }

    // Check entropy: count distinct byte values
    const distinctValues = new Set(randomBytes);
    if (distinctValues.size < MIN_DISTINCT_BYTE_VALUES) {
      return { healthy: false, error: "rng_low_entropy" };
    }

    return { healthy: true };
  }

  private isAllSameByte(bytes: Uint8Array, value: number): boolean {
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== value) return false;
    }
    return true;
  }
}
