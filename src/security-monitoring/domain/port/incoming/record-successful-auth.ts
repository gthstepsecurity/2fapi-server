// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RecordSuccessfulAuthRequest {
  readonly clientIdentifier: string;
}

export interface RecordSuccessfulAuthResponse {
  readonly recorded: true;
}

export interface RecordSuccessfulAuth {
  execute(request: RecordSuccessfulAuthRequest): Promise<RecordSuccessfulAuthResponse>;
}
