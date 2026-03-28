// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
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
export declare class DebugDetector {
    private readonly clock;
    private readonly emergencyZeroize;
    private readonly watchdogTimeoutMs;
    private watchdogTimer;
    private aborted;
    constructor(clock: (() => number) | undefined, emergencyZeroize: () => void, watchdogTimeoutMs?: number);
    /**
     * Start the watchdog timer. If not cancelled within timeout,
     * ALL secrets are emergency-zeroized.
     */
    startWatchdog(): void;
    /**
     * Cancel the watchdog (authentication completed normally).
     */
    cancelWatchdog(): void;
    /**
     * Execute an operation with timing guard.
     * If the operation takes longer than maxMs × 100, abort and zeroize.
     *
     * @param op - the operation to guard
     * @param maxExpectedMs - the maximum expected duration in normal execution
     * @param label - operation name for diagnostics
     */
    guarded<T>(op: () => Promise<T>, maxExpectedMs: number, label: string): Promise<T>;
    /**
     * Synchronous timing guard for WASM operations.
     */
    guardedSync<T>(op: () => T, maxExpectedMs: number, label: string): T;
    get isAborted(): boolean;
}
//# sourceMappingURL=debug-detector.d.ts.map
