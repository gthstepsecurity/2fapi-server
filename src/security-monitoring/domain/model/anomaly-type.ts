// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Known anomaly types detected by the Security Monitoring engine.
 */
export type AnomalyType =
  | "distributed_brute_force"
  | "volume_anomaly"
  | "mass_lockout"
  | "revoked_client_activity";
