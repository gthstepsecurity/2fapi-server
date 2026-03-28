// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { ChallengeId } from "./challenge-id.js";
import { Nonce } from "./nonce.js";
import { ChannelBinding } from "./channel-binding.js";
import { ChallengeExpiry } from "./challenge-expiry.js";
import type { FirstFactorType } from "./first-factor-type.js";

export type ChallengeStatus = "pending" | "used" | "invalidated";

export class Challenge {
  private constructor(
    readonly id: ChallengeId,
    readonly clientIdentifier: string,
    readonly nonce: Nonce,
    readonly channelBinding: ChannelBinding,
    readonly expiry: ChallengeExpiry,
    readonly firstFactorType: FirstFactorType,
    readonly status: ChallengeStatus,
  ) {}

  static issue(
    id: ChallengeId,
    clientIdentifier: string,
    nonce: Nonce,
    channelBinding: ChannelBinding,
    expiry: ChallengeExpiry,
    firstFactorType: FirstFactorType,
  ): Challenge {
    return new Challenge(id, clientIdentifier, nonce, channelBinding, expiry, firstFactorType, "pending");
  }

  invalidate(): Challenge {
    if (this.status !== "pending") {
      throw new Error("Cannot invalidate a non-pending challenge");
    }
    return new Challenge(
      this.id, this.clientIdentifier, this.nonce, this.channelBinding,
      this.expiry, this.firstFactorType, "invalidated",
    );
  }

  markUsed(): Challenge {
    if (this.status !== "pending") {
      throw new Error("Cannot mark a non-pending challenge as used");
    }
    return new Challenge(
      this.id, this.clientIdentifier, this.nonce, this.channelBinding,
      this.expiry, this.firstFactorType, "used",
    );
  }

  isValidAt(nowMs: number): boolean {
    return this.status === "pending" && this.expiry.isValidAt(nowMs);
  }
}
