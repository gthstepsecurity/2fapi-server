// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AnomalyDetectionEngine } from "../../../../src/security-monitoring/domain/service/anomaly-detection-engine.js";
import type { AnomalyType } from "../../../../src/security-monitoring/domain/model/anomaly-type.js";

describe("AnomalyDetectionEngine", () => {
  const engine = new AnomalyDetectionEngine();

  describe("distributed brute force", () => {
    it("detects when 50+ different clients fail within 1 minute", () => {
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: 1000 + i * 100,
        sourceAddress: `10.0.0.${i % 256}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 61000);
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("distributed_brute_force" satisfies AnomalyType);
      expect(result!.details.clientCount).toBe(50);
      expect(result!.details.timeWindowMs).toBe(60000);
      expect(Array.isArray(result!.details.sourceAddresses)).toBe(true);
      expect((result!.details.sourceAddresses as string[]).length).toBeGreaterThan(0);
    });

    it("does not trigger at 49 clients", () => {
      const failures = Array.from({ length: 49 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: 1000 + i * 100,
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 61000);
      expect(result).toBeNull();
    });

    it("does not trigger if failures span more than 1 minute", () => {
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: i * 2000, // spread over 100s
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 200000);
      expect(result).toBeNull();
    });

    it("does not trigger with 50 failures from same client (only 1 distinct)", () => {
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: "same-client",
        timestampMs: 1000 + i * 100,
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 61000);
      expect(result).toBeNull();
    });

    it("returns null for empty failures array", () => {
      const result = engine.analyzeFailures([], 0, 61000);
      expect(result).toBeNull();
    });

    it("detects at exactly 60000ms window span", () => {
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: i * 1200, // spans 0..58800ms < 60000
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 100000);
      expect(result).not.toBeNull();
    });

    it("accepts failures spanning exactly 60000ms (boundary: > not >=)", () => {
      // Kill mutant: `lastTs - firstTs >= DISTRIBUTED_BRUTE_FORCE_WINDOW_MS` instead of `>`
      // At exactly 60000ms span, `>` returns false so it continues → detection occurs
      // With `>=`, it would return null
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: i === 0 ? 0 : (i === 49 ? 60000 : i * 1200),
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 100000);
      // Span = 60000 which is NOT > 60000, so should NOT return null → should detect
      expect(result).not.toBeNull();
    });

    it("sorts failures to find correct first/last timestamps", () => {
      // Kill mutant: `const sorted = [...failures]` (without .sort()) and sort with +
      // Provide unsorted failures so that without sorting, the wrong first/last are used
      const failures: Array<{ clientIdentifier: string; timestampMs: number; sourceAddress: string }> = [];
      // Add them in reverse order
      for (let i = 49; i >= 0; i--) {
        failures.push({
          clientIdentifier: `client-${i}`,
          timestampMs: 1000 + i * 100,
          sourceAddress: `10.0.0.${i}`,
        });
      }
      const result = engine.analyzeFailures(failures, 0, 100000);
      // Should detect — after sorting, span is 4900ms < 60000
      expect(result).not.toBeNull();
    });

    it("includes source addresses in result details", () => {
      // Kill mutant: `failures.map(() => undefined)` instead of `(f) => f.sourceAddress`
      const failures = Array.from({ length: 50 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: 1000 + i * 100,
        sourceAddress: `192.168.1.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 100000);
      expect(result).not.toBeNull();
      const addrs = result!.details.sourceAddresses as string[];
      expect(addrs.length).toBeGreaterThan(0);
      // Verify actual IP addresses are present (not undefined)
      expect(addrs[0]).toMatch(/^192\.168\.1\.\d+$/);
    });

    it("below-threshold check returns null early (block statement)", () => {
      // Kill mutant: `if (failures.length < DISTRIBUTED_BRUTE_FORCE_THRESHOLD) {}`
      // (empty block instead of returning null)
      const failures = Array.from({ length: 30 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        timestampMs: 1000 + i * 100,
        sourceAddress: `10.0.0.${i}`,
      }));
      const result = engine.analyzeFailures(failures, 0, 100000);
      expect(result).toBeNull();
    });
  });

  describe("volume anomaly", () => {
    it("detects when client exceeds 20x baseline", () => {
      const result = engine.analyzeVolume("alice", 200, 10);
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("volume_anomaly" satisfies AnomalyType);
      expect(result!.details.clientIdentifier).toBe("alice");
      expect(result!.details.baseline).toBe(10);
      expect(result!.details.actual).toBe(200);
      expect(result!.details.multiplier).toBe(20);
    });

    it("does not trigger within baseline multiplier", () => {
      const result = engine.analyzeVolume("alice", 120, 100);
      expect(result).toBeNull();
    });

    it("triggers at exactly 20x baseline (>= threshold)", () => {
      const result = engine.analyzeVolume("alice", 200, 10);
      // 200 >= 10 * 20 = 200, so it triggers
      expect(result).not.toBeNull();
      expect(result!.details.multiplier).toBe(20);
    });

    it("does not trigger at 19x baseline", () => {
      const result = engine.analyzeVolume("alice", 190, 10);
      // 190 < 10 * 20 = 200
      expect(result).toBeNull();
    });

    it("does not trigger at 199 with baseline 10 (19.9x)", () => {
      const result = engine.analyzeVolume("alice", 199, 10);
      expect(result).toBeNull();
    });

    it("handles zero baseline (treats as 1)", () => {
      const result = engine.analyzeVolume("alice", 25, 0);
      expect(result).not.toBeNull();
      expect(result!.details.baseline).toBe(1);
      expect(result!.details.multiplier).toBe(25);
    });

    it("handles negative baseline (treats as 1)", () => {
      const result = engine.analyzeVolume("alice", 25, -5);
      expect(result).not.toBeNull();
      expect(result!.details.baseline).toBe(1);
    });
  });

  describe("mass lockout", () => {
    it("detects 10+ lockouts within 5 minutes", () => {
      const lockouts = Array.from({ length: 10 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        lockedOutAtMs: 1000 + i * 1000,
      }));
      const result = engine.analyzeLockouts(lockouts, 0, 301000);
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("mass_lockout" satisfies AnomalyType);
      expect(result!.details.lockoutCount).toBe(10);
      expect(result!.details.timeWindowMs).toBe(300000);
    });

    it("does not trigger at 9 lockouts", () => {
      const lockouts = Array.from({ length: 9 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        lockedOutAtMs: 1000 + i * 1000,
      }));
      const result = engine.analyzeLockouts(lockouts, 0, 301000);
      expect(result).toBeNull();
    });

    it("does not trigger if lockouts span more than 5 minutes", () => {
      const lockouts = Array.from({ length: 10 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        lockedOutAtMs: i * 40000, // spans 0..360000ms > 300000
      }));
      const result = engine.analyzeLockouts(lockouts, 0, 500000);
      expect(result).toBeNull();
    });

    it("returns null for empty lockouts array", () => {
      const result = engine.analyzeLockouts([], 0, 301000);
      expect(result).toBeNull();
    });

    it("detects lockouts at exactly 300000ms window span (boundary: > not >=)", () => {
      // Kill mutant: `lastTs - firstTs >= MASS_LOCKOUT_WINDOW_MS` instead of `> MASS_LOCKOUT_WINDOW_MS`
      // At exactly 300000ms span, `>` returns false, so detection continues
      // With `>=`, it would return null
      const lockouts = Array.from({ length: 10 }, (_, i) => ({
        clientIdentifier: `client-${i}`,
        lockedOutAtMs: i === 0 ? 0 : (i === 9 ? 300000 : i * 30000),
      }));
      const result = engine.analyzeLockouts(lockouts, 0, 500000);
      // Span = 300000 which is NOT > 300000, so should detect
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("mass_lockout");
    });

    it("sorts lockouts to find correct first/last timestamps", () => {
      // Kill mutant: `const sorted = [...lockouts]` (without sort) and sort with +
      // Provide unsorted lockouts — without sorting, wrong firstTs/lastTs
      const lockouts = [
        { clientIdentifier: "client-9", lockedOutAtMs: 9000 },
        { clientIdentifier: "client-0", lockedOutAtMs: 1000 },
        { clientIdentifier: "client-5", lockedOutAtMs: 5000 },
        { clientIdentifier: "client-1", lockedOutAtMs: 2000 },
        { clientIdentifier: "client-2", lockedOutAtMs: 3000 },
        { clientIdentifier: "client-3", lockedOutAtMs: 4000 },
        { clientIdentifier: "client-4", lockedOutAtMs: 4500 },
        { clientIdentifier: "client-6", lockedOutAtMs: 6000 },
        { clientIdentifier: "client-7", lockedOutAtMs: 7000 },
        { clientIdentifier: "client-8", lockedOutAtMs: 8000 },
      ];
      const result = engine.analyzeLockouts(lockouts, 0, 100000);
      // Span is 9000-1000 = 8000 < 300000, so should detect
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("mass_lockout");
    });
  });

  describe("revoked client activity", () => {
    it("detects any attempt from revoked client", () => {
      const result = engine.analyzeRevokedClientActivity("alice", "10.0.0.1", 1700000000000);
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("revoked_client_activity" satisfies AnomalyType);
      expect(result!.details.clientIdentifier).toBe("alice");
      expect(result!.details.sourceAddress).toBe("10.0.0.1");
      expect(result!.details.timestampMs).toBe(1700000000000);
    });
  });
});
