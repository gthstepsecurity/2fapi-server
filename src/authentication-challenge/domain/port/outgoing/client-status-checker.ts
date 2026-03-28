// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface LockoutInfo {
  readonly isLockedOut: boolean;
  readonly failedAttempts: number;
}

export interface ClientStatusChecker {
  getLockoutInfo(clientIdentifier: string): Promise<LockoutInfo>;
  recordFailedAttempt(clientIdentifier: string): Promise<void>;
}
