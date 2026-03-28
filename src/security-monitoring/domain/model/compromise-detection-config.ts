// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface CompromiseDetectionConfigInput {
  readonly ipBindingEnabled: boolean;
  readonly concurrentSessionWindowMs: number;
  readonly geoSpeedThresholdKmH: number;
  readonly autoSuspendOnAnomaly: boolean;
}

/**
 * Value object holding all configurable thresholds for compromise detection.
 * Immutable — frozen at creation.
 */
export class CompromiseDetectionConfig {
  readonly ipBindingEnabled: boolean;
  readonly concurrentSessionWindowMs: number;
  readonly geoSpeedThresholdKmH: number;
  readonly autoSuspendOnAnomaly: boolean;

  private constructor(input: CompromiseDetectionConfigInput) {
    this.ipBindingEnabled = input.ipBindingEnabled;
    this.concurrentSessionWindowMs = input.concurrentSessionWindowMs;
    this.geoSpeedThresholdKmH = input.geoSpeedThresholdKmH;
    this.autoSuspendOnAnomaly = input.autoSuspendOnAnomaly;
    Object.freeze(this);
  }

  static create(input: CompromiseDetectionConfigInput): CompromiseDetectionConfig {
    if (input.concurrentSessionWindowMs <= 0) {
      throw new Error("Concurrent session window must be positive");
    }
    if (input.geoSpeedThresholdKmH <= 0) {
      throw new Error("Geo speed threshold must be positive");
    }
    return new CompromiseDetectionConfig(input);
  }

  static defaults(): CompromiseDetectionConfig {
    return new CompromiseDetectionConfig({
      ipBindingEnabled: true,
      concurrentSessionWindowMs: 60_000,
      geoSpeedThresholdKmH: 900,
      autoSuspendOnAnomaly: true,
    });
  }
}
