// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value Object representing a DPoP (Demonstrating Proof-of-Possession)
 * proof as defined in RFC 9449.
 *
 * Contains the essential claims from the DPoP proof JWT:
 * - jti: unique identifier to prevent replay
 * - iat: issued-at timestamp (seconds since epoch)
 * - thumbprint: SHA-256 JWK thumbprint of the ephemeral public key
 * - httpMethod: the HTTP method of the request being bound
 * - httpUri: the HTTP URI of the request being bound
 */
export interface DpopProofInput {
  readonly jti: string;
  readonly iat: number;
  readonly thumbprint: string;
  readonly httpMethod: string;
  readonly httpUri: string;
}

export class DpopProof {
  readonly jti: string;
  readonly iat: number;
  readonly thumbprint: string;
  readonly httpMethod: string;
  readonly httpUri: string;

  private constructor(input: DpopProofInput) {
    this.jti = input.jti;
    this.iat = input.iat;
    this.thumbprint = input.thumbprint;
    this.httpMethod = input.httpMethod;
    this.httpUri = input.httpUri;
  }

  static create(input: DpopProofInput): DpopProof {
    if (input.jti.length === 0) {
      throw new Error("jti must not be empty");
    }
    if (input.thumbprint.length === 0) {
      throw new Error("thumbprint must not be empty");
    }
    return new DpopProof(input);
  }

  /**
   * Checks whether this proof's iat is too old relative to the current time.
   * @param nowSeconds Current time in seconds since epoch
   * @param maxAgeSec Maximum allowed age in seconds
   */
  isExpiredAt(nowSeconds: number, maxAgeSec: number): boolean {
    return nowSeconds - this.iat > maxAgeSec;
  }
}
