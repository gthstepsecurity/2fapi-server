// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FailedAttemptTracker } from "../../../domain/port/outgoing/failed-attempt-tracker.js";

export class StubFailedAttemptTracker implements FailedAttemptTracker {
  readonly recordedAttempts: string[] = [];
  readonly resetCalls: string[] = [];

  async recordFailedAttempt(clientIdentifier: string): Promise<void> {
    this.recordedAttempts.push(clientIdentifier);
  }

  async resetFailedAttempts(clientIdentifier: string): Promise<void> {
    this.resetCalls.push(clientIdentifier);
  }
}
