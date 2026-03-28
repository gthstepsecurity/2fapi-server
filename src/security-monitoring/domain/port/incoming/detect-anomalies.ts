// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AnomalyAlert } from "../../model/anomaly-alert.js";

export interface DetectAnomaliesRequest {
  readonly windowMs: number;
}

export interface DetectAnomaliesResponse {
  readonly alerts: readonly AnomalyAlert[];
}

export interface DetectAnomalies {
  execute(request: DetectAnomaliesRequest): Promise<DetectAnomaliesResponse>;
}
