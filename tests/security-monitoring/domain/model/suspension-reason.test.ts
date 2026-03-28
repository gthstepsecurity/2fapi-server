// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  SuspensionReason,
  VALID_SUSPENSION_REASONS,
} from "../../../../src/security-monitoring/domain/model/suspension-reason.js";

describe("SuspensionReason", () => {
  it.each([
    "concurrent_session",
    "geographic_impossibility",
    "volume_anomaly",
    "manual",
  ] as const)("creates a valid reason: %s", (reason) => {
    const sr = SuspensionReason.from(reason);
    expect(sr.value).toBe(reason);
  });

  it("is immutable — frozen after creation", () => {
    const sr = SuspensionReason.from("manual");
    expect(Object.isFrozen(sr)).toBe(true);
  });

  it("rejects unknown reason", () => {
    expect(() => SuspensionReason.from("unknown_reason" as any)).toThrow(
      "Invalid suspension reason",
    );
  });

  it("rejects empty reason", () => {
    expect(() => SuspensionReason.from("" as any)).toThrow(
      "Invalid suspension reason",
    );
  });

  it("exports the list of valid reasons", () => {
    expect(VALID_SUSPENSION_REASONS).toContain("concurrent_session");
    expect(VALID_SUSPENSION_REASONS).toContain("geographic_impossibility");
    expect(VALID_SUSPENSION_REASONS).toContain("volume_anomaly");
    expect(VALID_SUSPENSION_REASONS).toContain("manual");
    expect(VALID_SUSPENSION_REASONS).toHaveLength(4);
  });

  it("two reasons with same value are equal", () => {
    const a = SuspensionReason.from("manual");
    const b = SuspensionReason.from("manual");
    expect(a.equals(b)).toBe(true);
  });

  it("two reasons with different values are not equal", () => {
    const a = SuspensionReason.from("manual");
    const b = SuspensionReason.from("volume_anomaly");
    expect(a.equals(b)).toBe(false);
  });
});
