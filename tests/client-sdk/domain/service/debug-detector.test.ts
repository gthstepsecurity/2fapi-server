// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DebugDetector } from "../../../../packages/client-sdk/src/domain/service/debug-detector.js";

describe("DebugDetector", () => {
  it("guarded operation passes when timing is normal", async () => {
    let zeroized = false;
    const detector = new DebugDetector(
      () => performance.now(),
      () => { zeroized = true; },
    );

    const result = await detector.guarded(async () => "ok", 100, "test");
    expect(result).toBe("ok");
    expect(zeroized).toBe(false);
  });

  it("guarded operation triggers zeroize when timing anomaly detected", async () => {
    let zeroized = false;
    let clockMs = 0;
    const detector = new DebugDetector(
      () => { clockMs += 50_000; return clockMs; }, // each call = +50s (simulates debugger freeze)
      () => { zeroized = true; },
    );

    await expect(
      detector.guarded(async () => "result", 1, "oprf_blind")
    ).rejects.toThrow("Timing anomaly");
    expect(zeroized).toBe(true);
    expect(detector.isAborted).toBe(true);
  });

  it("subsequent operations fail after abort", async () => {
    let clockMs = 0;
    const detector = new DebugDetector(
      () => { clockMs += 50_000; return clockMs; },
      () => {},
    );

    // First op triggers abort
    await expect(detector.guarded(async () => {}, 1, "op1")).rejects.toThrow();

    // Second op fails immediately
    await expect(detector.guarded(async () => {}, 1000, "op2")).rejects.toThrow("aborted");
  });

  it("watchdog triggers zeroize after timeout", async () => {
    let zeroized = false;
    const detector = new DebugDetector(
      () => performance.now(),
      () => { zeroized = true; },
      50, // 50ms watchdog (short for testing)
    );

    detector.startWatchdog();
    await new Promise(r => setTimeout(r, 100)); // wait for watchdog to fire
    expect(zeroized).toBe(true);
  });

  it("watchdog does not fire if cancelled in time", async () => {
    let zeroized = false;
    const detector = new DebugDetector(
      () => performance.now(),
      () => { zeroized = true; },
      200,
    );

    detector.startWatchdog();
    await new Promise(r => setTimeout(r, 10)); // quick operation
    detector.cancelWatchdog();
    await new Promise(r => setTimeout(r, 300)); // wait past watchdog timeout
    expect(zeroized).toBe(false); // cancelled in time
  });

  it("guardedSync works for synchronous WASM operations", () => {
    let zeroized = false;
    const detector = new DebugDetector(
      () => performance.now(),
      () => { zeroized = true; },
    );

    const result = detector.guardedSync(() => 42, 100, "wasm_op");
    expect(result).toBe(42);
    expect(zeroized).toBe(false);
  });
});
