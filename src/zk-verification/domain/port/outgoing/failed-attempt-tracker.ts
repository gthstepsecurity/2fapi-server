// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface FailedAttemptTracker {
  recordFailedAttempt(clientIdentifier: string): Promise<void>;
  resetFailedAttempts(clientIdentifier: string): Promise<void>;
}
