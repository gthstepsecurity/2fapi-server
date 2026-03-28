// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface ReactivateViaExternalRequest {
  readonly clientIdentifier: string;
  readonly adminIdentity: string;
  readonly newCommitmentBytes: Uint8Array;
  readonly newCommitmentProofBytes: Uint8Array;
}

export type ReactivateViaExternalResponse =
  | { success: true }
  | { success: false; error: "reactivation_failed" };

export interface ReactivateViaExternal {
  execute(request: ReactivateViaExternalRequest): Promise<ReactivateViaExternalResponse>;
}
