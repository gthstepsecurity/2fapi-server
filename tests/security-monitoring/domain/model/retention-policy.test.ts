// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RetentionPolicy } from "../../../../src/security-monitoring/domain/model/retention-policy.js";

describe("RetentionPolicy", () => {
  it("creates standard retention (12 months)", () => {
    const policy = RetentionPolicy.standard();
    expect(policy.type).toBe("standard");
    expect(policy.durationMonths).toBe(12);
  });

  it("creates regulated retention (5 years = 60 months)", () => {
    const policy = RetentionPolicy.regulated();
    expect(policy.type).toBe("regulated");
    expect(policy.durationMonths).toBe(60);
  });

  it("determines if entry is within retention (standard)", () => {
    const policy = RetentionPolicy.standard();
    // Entry from Jan 15, 2026
    const entryTimestampMs = new Date("2026-01-15").getTime();
    // Check on Jun 15, 2026 (6 months later) — within 12 months
    const nowMs = new Date("2026-06-15").getTime();
    expect(policy.isWithinRetention(entryTimestampMs, nowMs)).toBe(true);
  });

  it("determines if entry is expired (standard)", () => {
    const policy = RetentionPolicy.standard();
    const entryTimestampMs = new Date("2026-01-15").getTime();
    // Check on Feb 15, 2027 (13 months later) — beyond 12 months
    const nowMs = new Date("2027-02-15").getTime();
    expect(policy.isWithinRetention(entryTimestampMs, nowMs)).toBe(false);
  });

  it("regulated policy retains for 5 years", () => {
    const policy = RetentionPolicy.regulated();
    const entryTimestampMs = new Date("2026-01-15").getTime();
    // Check on Jan 14, 2031 — within 5 years
    const withinMs = new Date("2031-01-14").getTime();
    expect(policy.isWithinRetention(entryTimestampMs, withinMs)).toBe(true);
    // Check on Feb 15, 2031 — beyond 5 years
    const beyondMs = new Date("2031-02-15").getTime();
    expect(policy.isWithinRetention(entryTimestampMs, beyondMs)).toBe(false);
  });

  it("boundary: entry at exactly retention limit is within retention (<= not <)", () => {
    // Kill mutant: `nowMs - entryTimestampMs < retentionMs` instead of `<=`
    const policy = RetentionPolicy.standard(); // 12 months
    const avgMsPerMonth = 30.44 * 24 * 60 * 60 * 1000;
    const retentionMs = 12 * avgMsPerMonth;
    const entryTimestampMs = 0;
    // Check at exactly the retention boundary
    expect(policy.isWithinRetention(entryTimestampMs, retentionMs)).toBe(true);
    // One ms beyond should be expired
    expect(policy.isWithinRetention(entryTimestampMs, retentionMs + 1)).toBe(false);
  });
});
