// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RevokeClientRequest {
  readonly clientIdentifier: string;
  readonly adminIdentity: string;
}

export type RevokeClientResponse =
  | { success: true }
  | { success: false; error: "revocation_failed" };

export interface RevokeClient {
  execute(request: RevokeClientRequest): Promise<RevokeClientResponse>;
}
