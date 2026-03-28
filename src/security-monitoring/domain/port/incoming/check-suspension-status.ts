// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Driving port for checking if a client is currently suspended.
 * Returns a simple active/suspended status without disclosing the reason.
 */
export interface CheckSuspensionStatusRequest {
  readonly clientIdentifier: string;
}

export interface CheckSuspensionStatusResponse {
  readonly status: "active" | "suspended";
}

export interface CheckSuspensionStatus {
  execute(request: CheckSuspensionStatusRequest): Promise<CheckSuspensionStatusResponse>;
}
