// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Anti-corruption layer for the Authentication Challenge bounded context.
 * Checks and consumes a challenge in a single atomic operation.
 */
/**
 * Returned by consumeIfValid when the challenge is valid and has been consumed.
 * A null return indicates the challenge was already consumed, expired, or unknown.
 * The existence of this object implies validity — no separate `valid` flag needed.
 */
export interface ChallengeInfo {
  readonly clientIdentifier: string;
  readonly nonce: Uint8Array;
  readonly channelBinding: Uint8Array;
}

export interface ChallengeConsumer {
  consumeIfValid(challengeId: string): Promise<ChallengeInfo | null>;
}
