// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CompromiseDetectionConfig } from "../../../../src/security-monitoring/domain/model/compromise-detection-config.js";

describe("CompromiseDetectionConfig", () => {
  it("creates a config with all thresholds", () => {
    const config = CompromiseDetectionConfig.create({
      ipBindingEnabled: true,
      concurrentSessionWindowMs: 60_000,
      geoSpeedThresholdKmH: 900,
      autoSuspendOnAnomaly: true,
    });

    expect(config.ipBindingEnabled).toBe(true);
    expect(config.concurrentSessionWindowMs).toBe(60_000);
    expect(config.geoSpeedThresholdKmH).toBe(900);
    expect(config.autoSuspendOnAnomaly).toBe(true);
  });

  it("is immutable — frozen after creation", () => {
    const config = CompromiseDetectionConfig.create({
      ipBindingEnabled: true,
      concurrentSessionWindowMs: 60_000,
      geoSpeedThresholdKmH: 900,
      autoSuspendOnAnomaly: true,
    });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it("provides sensible defaults", () => {
    const config = CompromiseDetectionConfig.defaults();

    expect(config.ipBindingEnabled).toBe(true);
    expect(config.concurrentSessionWindowMs).toBe(60_000);
    expect(config.geoSpeedThresholdKmH).toBe(900);
    expect(config.autoSuspendOnAnomaly).toBe(true);
  });

  it("rejects negative concurrent session window", () => {
    expect(() =>
      CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: -1,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      }),
    ).toThrow("Concurrent session window must be positive");
  });

  it("rejects zero concurrent session window", () => {
    expect(() =>
      CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 0,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      }),
    ).toThrow("Concurrent session window must be positive");
  });

  it("rejects negative geo speed threshold", () => {
    expect(() =>
      CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: -1,
        autoSuspendOnAnomaly: true,
      }),
    ).toThrow("Geo speed threshold must be positive");
  });

  it("rejects zero geo speed threshold", () => {
    expect(() =>
      CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 0,
        autoSuspendOnAnomaly: true,
      }),
    ).toThrow("Geo speed threshold must be positive");
  });

  it("allows disabling IP binding", () => {
    const config = CompromiseDetectionConfig.create({
      ipBindingEnabled: false,
      concurrentSessionWindowMs: 60_000,
      geoSpeedThresholdKmH: 900,
      autoSuspendOnAnomaly: true,
    });
    expect(config.ipBindingEnabled).toBe(false);
  });

  it("allows alert-only mode (no auto-suspend)", () => {
    const config = CompromiseDetectionConfig.create({
      ipBindingEnabled: true,
      concurrentSessionWindowMs: 60_000,
      geoSpeedThresholdKmH: 900,
      autoSuspendOnAnomaly: false,
    });
    expect(config.autoSuspendOnAnomaly).toBe(false);
  });
});
