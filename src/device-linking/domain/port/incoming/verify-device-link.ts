// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/** Driving port — verify the linking code from the new device. */
export interface VerifyDeviceLink {
  execute(input: VerifyDeviceLinkInput): Promise<VerifyDeviceLinkResult>;
}

export interface VerifyDeviceLinkInput {
  readonly clientId: string;
  readonly hashHex: string;
}

/**
 * FIX Mitnick side-channel: only two possible outcomes.
 *
 * "success" and "refused" are BOTH 7 characters — JSON serialization
 * produces identical byte lengths, defeating TLS record size analysis.
 *
 * All failure modes return "refused" — attacker cannot distinguish
 * not_found from expired from hash_mismatch. No attemptsRemaining
 * leak. The caller (Device B) only needs to know: try again or stop.
 */
export type VerifyDeviceLinkResult =
  | { readonly status: "success" }
  | { readonly status: "refused" };
