// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { LockoutStatus } from "../../model/lockout-status.js";

export interface CheckLockoutStatusRequest {
  readonly clientIdentifier: string;
}

export interface CheckLockoutStatusResponse {
  readonly status: LockoutStatus;
  readonly consecutiveFailures: number;
}

export interface CheckLockoutStatus {
  execute(request: CheckLockoutStatusRequest): Promise<CheckLockoutStatusResponse>;
}
