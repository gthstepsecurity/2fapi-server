// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RecordFailedAttemptRequest {
  readonly clientIdentifier: string;
}

export type RecordFailedAttemptResponse =
  | { readonly recorded: true; readonly lockedOut: boolean; readonly consecutiveFailures: number }
  | { readonly recorded: false; readonly error: string };

export interface RecordFailedAttempt {
  execute(request: RecordFailedAttemptRequest): Promise<RecordFailedAttemptResponse>;
}
