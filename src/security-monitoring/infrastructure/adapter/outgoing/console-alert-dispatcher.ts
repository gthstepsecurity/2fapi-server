// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AlertDispatcher } from "../../../domain/port/outgoing/alert-dispatcher.js";
import type { AnomalyAlert } from "../../../domain/model/anomaly-alert.js";

/**
 * Console-based alert dispatcher for production use.
 *
 * Logs anomaly alerts to stdout with structured JSON format.
 * Suitable as a baseline alerting mechanism — real integrations
 * (PagerDuty, Slack, OpsGenie) can be added as future work by
 * implementing the same AlertDispatcher port.
 */
export class ConsoleAlertDispatcher implements AlertDispatcher {
  async dispatch(alert: AnomalyAlert): Promise<void> {
    const severity = alert.isCritical ? "CRITICAL" : "WARNING";
    const payload = {
      level: severity,
      type: alert.anomalyType,
      id: alert.id,
      detectedAt: new Date(alert.detectedAtMs).toISOString(),
      details: alert.details,
    };
    console.log(`[ALERT:${severity}] ${JSON.stringify(payload)}`);
  }
}
