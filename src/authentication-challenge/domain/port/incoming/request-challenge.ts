// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export type ChallengeErrorCode =
  | "challenge_refused"
  | "unsupported_protocol_version"
  | "rate_limited"
  | "service_unavailable";

export interface RequestChallengeRequest {
  readonly clientIdentifier: string;
  readonly credential: Uint8Array;
  readonly channelBinding: Uint8Array;
  readonly protocolVersion?: string;
}

export type RequestChallengeResponse =
  | {
      readonly success: true;
      readonly challengeId: string;
      readonly nonce: Uint8Array;
      readonly channelBinding: Uint8Array;
      readonly expiresAtMs: number;
      readonly protocolVersion: string;
      readonly legacyFirstFactor: boolean;
    }
  | {
      readonly success: false;
      readonly error: ChallengeErrorCode;
      readonly supportedVersions?: readonly string[];
    };

export interface RequestChallenge {
  execute(request: RequestChallengeRequest): Promise<RequestChallengeResponse>;
}
