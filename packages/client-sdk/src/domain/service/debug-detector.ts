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

const DEFAULT_WATCHDOG_TIMEOUT_MS = 5000; // 5 seconds (generous for slow devices)

export class DebugDetector {
  private watchdogTimer: ReturnType<typeof setTimeout> | null = null;
  private aborted = false;

  constructor(
    private readonly clock: () => number = () => performance.now(),
    private readonly emergencyZeroize: () => void,
    private readonly watchdogTimeoutMs: number = DEFAULT_WATCHDOG_TIMEOUT_MS,
  ) {}

  /**
   * Start the watchdog timer. If not cancelled within timeout,
   * ALL secrets are emergency-zeroized.
   */
  startWatchdog(): void {
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
  cancelWatchdog(): void {
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
  async guarded<T>(op: () => Promise<T>, maxExpectedMs: number, label: string): Promise<T> {
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
  guardedSync<T>(op: () => T, maxExpectedMs: number, label: string): T {
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

  get isAborted(): boolean {
    return this.aborted;
  }
}
