// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { SuspensionReasonValue } from "../../model/suspension-reason.js";

export interface DetectCompromiseRequest {
  readonly clientIdentifier: string;
  readonly sourceIp: string;
  readonly timestampMs: number;
}

export interface DetectCompromiseResponse {
  readonly anomalyDetected: boolean;
  readonly suspended: boolean;
  readonly reason: SuspensionReasonValue | null;
}

/**
 * Driving port for detecting compromise indicators after an authentication event.
 * Checks IP binding, concurrent sessions, and geographic impossibility.
 */
export interface DetectCompromise {
  execute(request: DetectCompromiseRequest): Promise<DetectCompromiseResponse>;
}
