// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyType } from "./anomaly-type.js";

const CRITICAL_TYPES: ReadonlySet<AnomalyType> = new Set([
  "distributed_brute_force",
  "mass_lockout",
  "revoked_client_activity",
]);

export interface AnomalyAlertInput {
  readonly id: string;
  readonly anomalyType: AnomalyType;
  readonly detectedAtMs: number;
  readonly details: Record<string, unknown>;
}

/**
 * Entity representing a detected anomaly alert.
 * Immutable — frozen at creation.
 */
export class AnomalyAlert {
  readonly id: string;
  readonly anomalyType: AnomalyType;
  readonly detectedAtMs: number;
  readonly details: Readonly<Record<string, unknown>>;
  readonly isCritical: boolean;

  private constructor(input: AnomalyAlertInput) {
    this.id = input.id;
    this.anomalyType = input.anomalyType;
    this.detectedAtMs = input.detectedAtMs;
    this.details = Object.freeze({ ...input.details });
    this.isCritical = CRITICAL_TYPES.has(input.anomalyType);
    Object.freeze(this);
  }

  static create(input: AnomalyAlertInput): AnomalyAlert {
    return new AnomalyAlert(input);
  }
}
