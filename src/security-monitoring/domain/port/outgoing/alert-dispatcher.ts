// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyAlert } from "../../model/anomaly-alert.js";

/**
 * Driven port for dispatching anomaly alerts (e.g., to on-call admins).
 */
export interface AlertDispatcher {
  dispatch(alert: AnomalyAlert): Promise<void>;
}
