// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RotateCommitmentRequest {
  readonly clientIdentifier: string;
  readonly currentProofBytes: Uint8Array;
  readonly newCommitmentBytes: Uint8Array;
  readonly newCommitmentProofBytes: Uint8Array;
}

export type RotateCommitmentResponse =
  | { success: true }
  | { success: false; error: "rotation_failed" };

export interface RotateCommitment {
  execute(request: RotateCommitmentRequest): Promise<RotateCommitmentResponse>;
}
