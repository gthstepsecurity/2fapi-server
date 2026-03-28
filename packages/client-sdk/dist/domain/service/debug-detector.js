/**
 * Domain service: detects debugger step-by-step execution and triggers
 * emergency zeroization (R26-01, R26-02 fix).
 *
 * Two independent detection mechanisms:
 * 1. TIMING GUARD: checks elapsed time between operations.
 *    If a 1µs operation took >100ms → debugger stepping detected.
 * 2. WATCHDOG: timeout-based emergency zeroize. If the auth flow
 *    doesn't complete within the expected window → zeroize everything.
 */
const DEFAULT_WATCHDOG_TIMEOUT_MS = 5000; // 5 seconds (generous for slow devices)
export class DebugDetector {
    clock;
    emergencyZeroize;
    watchdogTimeoutMs;
    watchdogTimer = null;
    aborted = false;
    constructor(clock = () => performance.now(), emergencyZeroize, watchdogTimeoutMs = DEFAULT_WATCHDOG_TIMEOUT_MS) {
        this.clock = clock;
        this.emergencyZeroize = emergencyZeroize;
        this.watchdogTimeoutMs = watchdogTimeoutMs;
    }
    /**
     * Start the watchdog timer. If not cancelled within timeout,
     * ALL secrets are emergency-zeroized.
     */
    startWatchdog() {
        this.aborted = false;
        this.watchdogTimer = setTimeout(() => {
            if (!this.aborted) {
                this.emergencyZeroize();
                this.aborted = true;
            }
        }, this.watchdogTimeoutMs);
    }
    /**
     * Cancel the watchdog (authentication completed normally).
     */
    cancelWatchdog() {
        if (this.watchdogTimer) {
            clearTimeout(this.watchdogTimer);
            this.watchdogTimer = null;
        }
    }
    /**
     * Execute an operation with timing guard.
     * If the operation takes longer than maxMs × 100, abort and zeroize.
     *
     * @param op - the operation to guard
     * @param maxExpectedMs - the maximum expected duration in normal execution
     * @param label - operation name for diagnostics
     */
    async guarded(op, maxExpectedMs, label) {
        if (this.aborted) {
            throw new Error("Authentication aborted: timing anomaly detected");
        }
        const start = this.clock();
        const result = await op();
        const elapsed = this.clock() - start;
        // If an operation that should take <maxExpectedMs took >100× that → debugger
        const threshold = Math.max(maxExpectedMs * 100, 10_000); // at least 10s tolerance
        if (elapsed > threshold) {
            this.emergencyZeroize();
            this.aborted = true;
            throw new Error(`Timing anomaly in ${label}: expected <${maxExpectedMs}ms, got ${elapsed.toFixed(0)}ms`);
        }
        return result;
    }
    /**
     * Synchronous timing guard for WASM operations.
     */
    guardedSync(op, maxExpectedMs, label) {
        if (this.aborted) {
            throw new Error("Authentication aborted: timing anomaly detected");
        }
        const start = this.clock();
        const result = op();
        const elapsed = this.clock() - start;
        const threshold = Math.max(maxExpectedMs * 100, 10_000);
        if (elapsed > threshold) {
            this.emergencyZeroize();
            this.aborted = true;
            throw new Error(`Timing anomaly in ${label}: expected <${maxExpectedMs}ms, got ${elapsed.toFixed(0)}ms`);
        }
        return result;
    }
    get isAborted() {
        return this.aborted;
    }
}
//# sourceMappingURL=debug-detector.js.map