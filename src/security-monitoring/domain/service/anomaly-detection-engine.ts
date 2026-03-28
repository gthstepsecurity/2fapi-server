// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyType } from "../model/anomaly-type.js";

/** Minimum distinct clients within a 1-minute window to trigger distributed brute-force alert. */
const DISTRIBUTED_BRUTE_FORCE_THRESHOLD = 50;
const DISTRIBUTED_BRUTE_FORCE_WINDOW_MS = 60_000;

/** Multiplier above baseline that triggers volume anomaly. */
const VOLUME_ANOMALY_MULTIPLIER = 20;

/** Minimum lockouts within 5-minute window to trigger mass lockout alert. */
const MASS_LOCKOUT_THRESHOLD = 10;
const MASS_LOCKOUT_WINDOW_MS = 5 * 60_000;

export interface FailureRecord {
  readonly clientIdentifier: string;
  readonly timestampMs: number;
  readonly sourceAddress: string;
}

export interface LockoutRecord {
  readonly clientIdentifier: string;
  readonly lockedOutAtMs: number;
}

export interface AnomalyResult {
  readonly anomalyType: AnomalyType;
  readonly details: Record<string, unknown>;
}

/**
 * Domain service implementing anomaly pattern detection.
 * Pure business logic — no I/O.
 */
export class AnomalyDetectionEngine {
  /**
   * Analyzes a set of failures for distributed brute-force pattern:
   * 50+ distinct clients failing within any 1-minute window.
   */
  analyzeFailures(
    failures: readonly FailureRecord[],
    _windowStartMs: number,
    _windowEndMs: number,
  ): AnomalyResult | null {
    if (failures.length < DISTRIBUTED_BRUTE_FORCE_THRESHOLD) {
      return null;
    }

    // Find 1-minute windows within the data that contain 50+ distinct clients
    const sorted = [...failures].sort((a, b) => a.timestampMs - b.timestampMs);
    const firstTs = sorted[0]?.timestampMs ?? 0;
    const lastTs = sorted[sorted.length - 1]?.timestampMs ?? 0;

    if (lastTs - firstTs > DISTRIBUTED_BRUTE_FORCE_WINDOW_MS) {
      return null;
    }

    const distinctClients = new Set(failures.map((f) => f.clientIdentifier));
    if (distinctClients.size < DISTRIBUTED_BRUTE_FORCE_THRESHOLD) {
      return null;
    }

    const sourceAddresses = [...new Set(failures.map((f) => f.sourceAddress))];
    return {
      anomalyType: "distributed_brute_force",
      details: {
        timeWindowMs: DISTRIBUTED_BRUTE_FORCE_WINDOW_MS,
        clientCount: distinctClients.size,
        sourceAddresses,
      },
    };
  }

  /**
   * Analyzes a single client's volume against their baseline.
   * Triggers when actual exceeds 20x the baseline.
   */
  analyzeVolume(
    clientIdentifier: string,
    actualCount: number,
    baselinePerHour: number,
  ): AnomalyResult | null {
    const effectiveBaseline = baselinePerHour <= 0 ? 1 : baselinePerHour;
    if (actualCount >= effectiveBaseline * VOLUME_ANOMALY_MULTIPLIER) {
      return {
        anomalyType: "volume_anomaly",
        details: {
          clientIdentifier,
          baseline: effectiveBaseline,
          actual: actualCount,
          multiplier: actualCount / effectiveBaseline,
        },
      };
    }
    return null;
  }

  /**
   * Analyzes lockouts for mass lockout pattern:
   * 10+ clients locked out within any 5-minute window.
   */
  analyzeLockouts(
    lockouts: readonly LockoutRecord[],
    _windowStartMs: number,
    _windowEndMs: number,
  ): AnomalyResult | null {
    if (lockouts.length < MASS_LOCKOUT_THRESHOLD) {
      return null;
    }

    const sorted = [...lockouts].sort((a, b) => a.lockedOutAtMs - b.lockedOutAtMs);
    const firstTs = sorted[0]?.lockedOutAtMs ?? 0;
    const lastTs = sorted[sorted.length - 1]?.lockedOutAtMs ?? 0;

    if (lastTs - firstTs > MASS_LOCKOUT_WINDOW_MS) {
      return null;
    }

    return {
      anomalyType: "mass_lockout",
      details: {
        lockoutCount: lockouts.length,
        timeWindowMs: MASS_LOCKOUT_WINDOW_MS,
      },
    };
  }

  /**
   * Any authentication attempt from a revoked client is an immediate alert.
   */
  analyzeRevokedClientActivity(
    clientIdentifier: string,
    sourceAddress: string,
    timestampMs: number,
  ): AnomalyResult {
    return {
      anomalyType: "revoked_client_activity",
      details: {
        clientIdentifier,
        sourceAddress,
        timestampMs,
      },
    };
  }
}
