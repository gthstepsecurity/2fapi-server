// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CompromiseDetectionEngine } from "../../../../src/security-monitoring/domain/service/compromise-detection-engine.js";
import { GeoLocation } from "../../../../src/security-monitoring/domain/model/geo-location.js";
import { CompromiseDetectionConfig } from "../../../../src/security-monitoring/domain/model/compromise-detection-config.js";

describe("CompromiseDetectionEngine", () => {
  const engine = new CompromiseDetectionEngine();
  const defaultConfig = CompromiseDetectionConfig.defaults();

  describe("detectIpAnomaly", () => {
    it("returns null when current IP matches previous IP", () => {
      const result = engine.detectIpAnomaly("alice", "203.0.113.10", "203.0.113.10");
      expect(result).toBeNull();
    });

    it("returns anomaly result when IPs differ", () => {
      const result = engine.detectIpAnomaly("alice", "203.0.113.10", "198.51.100.42");
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("ip_change");
      expect(result!.details.clientIdentifier).toBe("alice");
      expect(result!.details.currentIp).toBe("203.0.113.10");
      expect(result!.details.previousIp).toBe("198.51.100.42");
    });

    it("returns null when previous IP is null (first authentication)", () => {
      const result = engine.detectIpAnomaly("alice", "203.0.113.10", null);
      expect(result).toBeNull();
    });
  });

  describe("detectConcurrentSession", () => {
    it("returns null when same IP within time window", () => {
      const result = engine.detectConcurrentSession(
        "alice",
        "203.0.113.10",
        "203.0.113.10",
        30_000,
        defaultConfig,
      );
      expect(result).toBeNull();
    });

    it("returns anomaly when different IPs within time window", () => {
      const result = engine.detectConcurrentSession(
        "alice",
        "203.0.113.10",
        "198.51.100.42",
        30_000,
        defaultConfig,
      );
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("concurrent_session");
      expect(result!.details.clientIdentifier).toBe("alice");
      expect(result!.details.ip1).toBe("203.0.113.10");
      expect(result!.details.ip2).toBe("198.51.100.42");
      expect(result!.details.timeDeltaMs).toBe(30_000);
    });

    it("returns null when different IPs but outside time window", () => {
      const result = engine.detectConcurrentSession(
        "alice",
        "203.0.113.10",
        "198.51.100.42",
        120_000, // 2 minutes, beyond 60s window
        defaultConfig,
      );
      expect(result).toBeNull();
    });

    it("uses configurable time window", () => {
      const strictConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 30_000, // 30 seconds
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      });

      // 45 seconds apart — within default 60s but outside 30s window
      const result = engine.detectConcurrentSession(
        "alice",
        "203.0.113.10",
        "198.51.100.42",
        45_000,
        strictConfig,
      );
      expect(result).toBeNull();
    });

    it("detects within strict 30s window", () => {
      const strictConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 30_000,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      });

      const result = engine.detectConcurrentSession(
        "alice",
        "203.0.113.10",
        "198.51.100.42",
        25_000,
        strictConfig,
      );
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("concurrent_session");
    });
  });

  describe("detectGeographicImpossibility", () => {
    const paris = GeoLocation.create("1.1.1.1", 48.8566, 2.3522, "Paris", "FR");
    const tokyo = GeoLocation.create("2.2.2.2", 35.6762, 139.6503, "Tokyo", "JP");
    const london = GeoLocation.create("3.3.3.3", 51.5074, -0.1278, "London", "GB");

    it("detects Paris to Tokyo in 5 minutes as impossible", () => {
      const fiveMinMs = 5 * 60 * 1000;
      const result = engine.detectGeographicImpossibility(
        paris,
        tokyo,
        fiveMinMs,
        defaultConfig,
      );
      expect(result).not.toBeNull();
      expect(result!.anomalyType).toBe("geographic_impossibility");
      expect(result!.details.distanceKm).toBeGreaterThan(9600);
      expect(result!.details.requiredSpeedKmH).toBeGreaterThan(100000);
    });

    it("allows Paris to London in 2 hours (170 km/h < 900 km/h)", () => {
      const twoHoursMs = 2 * 60 * 60 * 1000;
      const result = engine.detectGeographicImpossibility(
        paris,
        london,
        twoHoursMs,
        defaultConfig,
      );
      expect(result).toBeNull();
    });

    it("returns null when locations are the same", () => {
      const result = engine.detectGeographicImpossibility(
        paris,
        paris,
        1000,
        defaultConfig,
      );
      expect(result).toBeNull();
    });

    it("returns null when time delta is zero (division by zero guard)", () => {
      const result = engine.detectGeographicImpossibility(
        paris,
        tokyo,
        0,
        defaultConfig,
      );
      // Zero time delta — we cannot compute speed, skip detection
      expect(result).toBeNull();
    });

    it("uses configurable speed threshold", () => {
      const strictConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 500, // stricter: 500 km/h
        autoSuspendOnAnomaly: true,
      });

      // Paris to Frankfurt (~450 km) in 30 min = 900 km/h
      const frankfurt = GeoLocation.create("4.4.4.4", 50.1109, 8.6821, "Frankfurt", "DE");
      const thirtyMinMs = 30 * 60 * 1000;
      const result = engine.detectGeographicImpossibility(
        paris,
        frankfurt,
        thirtyMinMs,
        strictConfig,
      );
      expect(result).not.toBeNull();
      expect(result!.details.requiredSpeedKmH).toBeGreaterThan(500);
    });

    it("allows travel below relaxed threshold", () => {
      const relaxedConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 1200, // relaxed: 1200 km/h
        autoSuspendOnAnomaly: true,
      });

      const frankfurt = GeoLocation.create("4.4.4.4", 50.1109, 8.6821, "Frankfurt", "DE");
      const thirtyMinMs = 30 * 60 * 1000;
      const result = engine.detectGeographicImpossibility(
        paris,
        frankfurt,
        thirtyMinMs,
        relaxedConfig,
      );
      expect(result).toBeNull();
    });

    it("includes location details in anomaly result", () => {
      const fiveMinMs = 5 * 60 * 1000;
      const result = engine.detectGeographicImpossibility(
        paris,
        tokyo,
        fiveMinMs,
        defaultConfig,
      );
      expect(result).not.toBeNull();
      expect(result!.details.from).toEqual({ city: "Paris", country: "FR" });
      expect(result!.details.to).toEqual({ city: "Tokyo", country: "JP" });
      expect(result!.details.timeDeltaMs).toBe(fiveMinMs);
      expect(result!.details.speedThresholdKmH).toBe(900);
    });
  });
});
