// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Stores per-client authentication baselines for anomaly detection.
 * A baseline represents the expected authentication volume per time window.
 */
export interface ClientBaseline {
  readonly clientIdentifier: string;
  readonly authsPerHour: number;
}

export interface AnomalyBaselineStore {
  getBaseline(clientIdentifier: string): Promise<ClientBaseline | null>;
  saveBaseline(baseline: ClientBaseline): Promise<void>;
}
