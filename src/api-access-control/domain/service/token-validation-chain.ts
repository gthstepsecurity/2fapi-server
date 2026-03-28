// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenClaims } from "../model/token-claims.js";
import type { Audience } from "../model/audience.js";

export type ValidationErrorCode =
  | "INVALID_SIGNATURE"
  | "TOKEN_EXPIRED"
  | "AUDIENCE_MISMATCH"
  | "CHANNEL_BINDING_MISMATCH"
  | "CLIENT_NOT_ACTIVE";

export class ValidationError extends Error {
  constructor(
    readonly code: ValidationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

export interface ValidationInput {
  readonly claims: TokenClaims;
  readonly signatureValid: boolean;
  readonly nowMs: number;
  readonly expectedAudience: Audience;
  readonly expectedChannelBindingHash: string;
  readonly clientActive: boolean;
}

/**
 * Ordered validation chain: signature → expiration → audience → cnf → client status.
 *
 * ALL steps are always executed regardless of intermediate failures
 * to ensure constant-time behavior (timing-safe). The first failure
 * encountered is reported, but no step is short-circuited.
 */
export class TokenValidationChain {
  validate(input: ValidationInput): ValidationError | null {
    let firstError: ValidationError | null = null;

    // Step 1: Signature
    if (!input.signatureValid) {
      firstError = firstError ?? new ValidationError(
        "INVALID_SIGNATURE",
        "Token signature is invalid",
      );
    }

    // Step 2: Expiration
    if (input.claims.isExpiredAt(input.nowMs)) {
      firstError = firstError ?? new ValidationError(
        "TOKEN_EXPIRED",
        "Token has expired",
      );
    }

    // Step 3: Audience
    if (!input.claims.hasAudience(input.expectedAudience)) {
      firstError = firstError ?? new ValidationError(
        "AUDIENCE_MISMATCH",
        "Token audience does not match",
      );
    }

    // Step 4: Channel binding (constant-time comparison in TokenClaims)
    if (!input.claims.hasChannelBinding(input.expectedChannelBindingHash)) {
      firstError = firstError ?? new ValidationError(
        "CHANNEL_BINDING_MISMATCH",
        "Channel binding does not match",
      );
    }

    // Step 5: Client status
    if (!input.clientActive) {
      firstError = firstError ?? new ValidationError(
        "CLIENT_NOT_ACTIVE",
        "Client is no longer active",
      );
    }

    return firstError;
  }
}
