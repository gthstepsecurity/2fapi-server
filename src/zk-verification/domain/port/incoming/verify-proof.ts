// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface VerifyProofRequest {
  readonly clientIdentifier: string;
  readonly challengeId: string;
  readonly proofBytes: Uint8Array;
  readonly channelBinding: Uint8Array;
  readonly domainSeparationTag: string;
}

export type VerifyProofResponse =
  | {
      readonly success: true;
      readonly clientIdentifier: string;
      readonly receiptId: string;
    }
  | {
      readonly success: false;
      readonly error: VerificationErrorCode;
    };

export type VerificationErrorCode =
  | "verification_refused"
  | "rate_limited";

export interface VerifyProof {
  execute(request: VerifyProofRequest): Promise<VerifyProofResponse>;
}
