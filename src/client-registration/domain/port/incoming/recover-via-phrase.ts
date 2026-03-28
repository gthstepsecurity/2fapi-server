// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RecoverViaPhraseRequest {
  readonly clientIdentifier: string;
  readonly words: readonly string[];
  readonly newCommitmentBytes: Uint8Array;
  readonly newCommitmentProofBytes: Uint8Array;
}

export type RecoverViaPhraseResponse =
  | { success: true; newRecoveryWords?: readonly string[] }
  | { success: false; error: "recovery_failed" };

export interface RecoverViaPhrase {
  execute(request: RecoverViaPhraseRequest): Promise<RecoverViaPhraseResponse>;
}
