// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object representing audit log retention duration.
 * Standard: 12 months. Regulated: 5 years (60 months).
 */
export class RetentionPolicy {
  private constructor(
    readonly type: "standard" | "regulated",
    readonly durationMonths: number,
  ) {}

  static standard(): RetentionPolicy {
    return new RetentionPolicy("standard", 12);
  }

  static regulated(): RetentionPolicy {
    return new RetentionPolicy("regulated", 60);
  }

  /**
   * Returns true if the entry is still within the retention window.
   * Uses approximate month-based calculation (30.44 days per month).
   */
  isWithinRetention(entryTimestampMs: number, nowMs: number): boolean {
    const avgMsPerMonth = 30.44 * 24 * 60 * 60 * 1000;
    const retentionMs = this.durationMonths * avgMsPerMonth;
    return nowMs - entryTimestampMs <= retentionMs;
  }
}
