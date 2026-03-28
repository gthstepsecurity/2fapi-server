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
export declare class TimingNormalizer {
    private readonly targetMs;
    private readonly jitterMs;
    private readonly clock;
    private readonly sleepFn;
    private readonly randomFn;
    constructor(targetMs?: number, jitterMs?: number, clock?: () => number, sleepFn?: (ms: number) => Promise<void>, randomFn?: () => number);
    /**
     * Execute an operation and pad the response time to target + random jitter.
     * R18-05 FIX: random jitter makes the distribution identical for all tiers,
     * defeating statistical analysis of setTimeout granularity differences.
     */
    normalize<T>(operation: () => Promise<T>): Promise<T>;
}
//# sourceMappingURL=timing-normalizer.d.ts.map
