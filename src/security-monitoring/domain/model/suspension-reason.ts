// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Valid suspension reason values.
 */
export const VALID_SUSPENSION_REASONS = [
  "concurrent_session",
  "geographic_impossibility",
  "volume_anomaly",
  "manual",
] as const;

export type SuspensionReasonValue = typeof VALID_SUSPENSION_REASONS[number];

const VALID_SET: ReadonlySet<string> = new Set(VALID_SUSPENSION_REASONS);

/**
 * Value object representing the reason a client was suspended.
 * Immutable — frozen at creation.
 */
export class SuspensionReason {
  readonly value: SuspensionReasonValue;

  private constructor(value: SuspensionReasonValue) {
    this.value = value;
    Object.freeze(this);
  }

  static from(reason: SuspensionReasonValue): SuspensionReason {
    if (!VALID_SET.has(reason)) {
      throw new Error("Invalid suspension reason");
    }
    return new SuspensionReason(reason);
  }

  equals(other: SuspensionReason): boolean {
    return this.value === other.value;
  }
}
