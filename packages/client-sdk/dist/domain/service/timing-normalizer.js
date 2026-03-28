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
export class TimingNormalizer {
    targetMs;
    jitterMs;
    clock;
    sleepFn;
    randomFn;
    constructor(targetMs = DEFAULT_TARGET_MS, jitterMs = DEFAULT_JITTER_MS, clock = () => Date.now(), sleepFn = (ms) => new Promise(r => setTimeout(r, ms)), randomFn = () => Math.random()) {
        this.targetMs = targetMs;
        this.jitterMs = jitterMs;
        this.clock = clock;
        this.sleepFn = sleepFn;
        this.randomFn = randomFn;
    }
    /**
     * Execute an operation and pad the response time to target + random jitter.
     * R18-05 FIX: random jitter makes the distribution identical for all tiers,
     * defeating statistical analysis of setTimeout granularity differences.
     */
    async normalize(operation) {
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
//# sourceMappingURL=timing-normalizer.js.map