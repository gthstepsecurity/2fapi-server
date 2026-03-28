// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { GeoLocation } from "../model/geo-location.js";
import type { CompromiseDetectionConfig } from "../model/compromise-detection-config.js";

export interface CompromiseAnomalyResult {
  readonly anomalyType: "ip_change" | "concurrent_session" | "geographic_impossibility";
  readonly details: Record<string, unknown>;
}

/**
 * Domain service implementing compromise pattern detection.
 * Pure business logic — no I/O.
 */
export class CompromiseDetectionEngine {
  /**
   * Detects IP change anomaly: current IP differs from previously known IP.
   * Returns null for first authentication (no previous IP) or same IP.
   */
  detectIpAnomaly(
    clientIdentifier: string,
    currentIp: string,
    previousIp: string | null,
  ): CompromiseAnomalyResult | null {
    if (previousIp === null) {
      return null;
    }
    if (currentIp === previousIp) {
      return null;
    }
    return {
      anomalyType: "ip_change",
      details: {
        clientIdentifier,
        currentIp,
        previousIp,
      },
    };
  }

  /**
   * Detects concurrent session: two different IPs used within the configurable time window.
   * Same-IP authentications within the window are always normal.
   */
  detectConcurrentSession(
    clientIdentifier: string,
    ip1: string,
    ip2: string,
    timeDeltaMs: number,
    config: CompromiseDetectionConfig,
  ): CompromiseAnomalyResult | null {
    if (ip1 === ip2) {
      return null;
    }
    if (timeDeltaMs > config.concurrentSessionWindowMs) {
      return null;
    }
    return {
      anomalyType: "concurrent_session",
      details: {
        clientIdentifier,
        ip1,
        ip2,
        timeDeltaMs,
        windowMs: config.concurrentSessionWindowMs,
      },
    };
  }

  /**
   * Detects geographic impossibility: travel between two locations at a speed
   * exceeding the configured threshold.
   * Uses great-circle distance (Haversine) from GeoLocation.
   * Returns null if time delta is zero or locations are the same.
   */
  detectGeographicImpossibility(
    loc1: GeoLocation,
    loc2: GeoLocation,
    timeDeltaMs: number,
    config: CompromiseDetectionConfig,
  ): CompromiseAnomalyResult | null {
    if (timeDeltaMs <= 0) {
      return null;
    }

    const distanceKm = loc1.distanceKm(loc2);
    if (distanceKm === 0) {
      return null;
    }

    const timeHours = timeDeltaMs / (1000 * 60 * 60);
    const requiredSpeedKmH = distanceKm / timeHours;

    if (requiredSpeedKmH <= config.geoSpeedThresholdKmH) {
      return null;
    }

    return {
      anomalyType: "geographic_impossibility",
      details: {
        from: { city: loc1.city, country: loc1.country },
        to: { city: loc2.city, country: loc2.country },
        distanceKm,
        timeDeltaMs,
        requiredSpeedKmH,
        speedThresholdKmH: config.geoSpeedThresholdKmH,
      },
    };
  }
}
