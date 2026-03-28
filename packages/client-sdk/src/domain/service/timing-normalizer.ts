// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: normalizes authentication response timing (R17-01 fix).
 *
 * All authentication tiers MUST respond in the same time window to prevent
 * an observer from distinguishing Tier 0 (passphrase, ~500ms) from
 * Tier 1 (vault, ~2ms) via response timing.
 *
 * Target: 500ms (the Argon2id cost, slowest mandatory operation).
 * Applied AFTER cryptographic operations, BEFORE HTTP response.
 * Does NOT delay zeroization (secrets are already cleared).
 */

const DEFAULT_TARGET_MS = 500;
const DEFAULT_JITTER_MS = 50;

/**
 * FIX C-01: cryptographically secure random float in [0, 1).
 *
 * Math.random() is NOT suitable for security-sensitive jitter because
 * its PRNG state is predictable after ~600 outputs (V8 xorshift128+).
 * An attacker can reconstruct the jitter sequence and strip the noise,
 * recovering the true operation timing to distinguish auth tiers.
 *
 * We use crypto.getRandomValues() which delegates to the OS CSPRNG.
 */
function cryptoRandomFloat(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return buf[0]! / 0x1_0000_0000; // [0, 1) with 32-bit resolution
}

export class TimingNormalizer {
  constructor(
    private readonly targetMs: number = DEFAULT_TARGET_MS,
    private readonly jitterMs: number = DEFAULT_JITTER_MS,
    private readonly clock: () => number = () => Date.now(),
    private readonly sleepFn: (ms: number) => Promise<void> = (ms) => new Promise(r => setTimeout(r, ms)),
    private readonly randomFn: () => number = cryptoRandomFloat,
  ) {}

  /**
   * Execute an operation and pad the response time to target + random jitter.
   * R18-05 FIX: random jitter makes the distribution identical for all tiers,
   * defeating statistical analysis of setTimeout granularity differences.
   */
  async normalize<T>(operation: () => Promise<T>): Promise<T> {
    const jitter = this.randomFn() * this.jitterMs;
    const effectiveTarget = this.targetMs + jitter;

    const start = this.clock();
    const result = await operation();
    const elapsed = this.clock() - start;

    if (elapsed < effectiveTarget) {
      await this.sleepFn(effectiveTarget - elapsed);
    }

    return result;
  }
}
