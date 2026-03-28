// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AlertDispatcher } from "../../../domain/port/outgoing/alert-dispatcher.js";
import type { AnomalyAlert } from "../../../domain/model/anomaly-alert.js";

/**
 * Stub alert dispatcher for testing — captures dispatched alerts.
 */
export class StubAlertDispatcher implements AlertDispatcher {
  readonly dispatched: AnomalyAlert[] = [];

  async dispatch(alert: AnomalyAlert): Promise<void> {
    this.dispatched.push(alert);
  }
}
