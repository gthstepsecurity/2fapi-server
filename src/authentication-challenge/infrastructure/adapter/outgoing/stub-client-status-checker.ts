// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ClientStatusChecker,
  LockoutInfo,
} from "../../../domain/port/outgoing/client-status-checker.js";

export class StubClientStatusChecker implements ClientStatusChecker {
  readonly recordedAttempts: string[] = [];

  constructor(private readonly lockoutInfo: LockoutInfo = { isLockedOut: false, failedAttempts: 0 }) {}

  async getLockoutInfo(): Promise<LockoutInfo> {
    return this.lockoutInfo;
  }

  async recordFailedAttempt(clientIdentifier: string): Promise<void> {
    this.recordedAttempts.push(clientIdentifier);
  }
}
