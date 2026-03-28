// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface CheckChallengeRequest {
  readonly challengeId: string;
}

export type CheckChallengeResponse =
  | {
      readonly valid: true;
      readonly clientIdentifier: string;
      readonly nonce: Uint8Array;
      readonly channelBinding: Uint8Array;
    }
  | {
      readonly valid: false;
      readonly reason: "expired" | "unknown";
    };

export interface CheckChallenge {
  execute(request: CheckChallengeRequest): Promise<CheckChallengeResponse>;
}
