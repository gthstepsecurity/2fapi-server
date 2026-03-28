// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyBaselineStore, ClientBaseline } from "../../../domain/port/outgoing/anomaly-baseline-store.js";

/**
 * In-memory reference implementation of AnomalyBaselineStore.
 * Initializes with a default baseline when no historical data exists.
 */
export class InMemoryAnomalyBaselineStore implements AnomalyBaselineStore {
  private readonly baselines = new Map<string, ClientBaseline>();

  async getBaseline(clientIdentifier: string): Promise<ClientBaseline | null> {
    return this.baselines.get(clientIdentifier) ?? null;
  }

  async saveBaseline(baseline: ClientBaseline): Promise<void> {
    this.baselines.set(baseline.clientIdentifier, baseline);
  }
}
