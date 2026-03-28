// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DpopProof } from "../../model/dpop-proof.js";

/**
 * Port for verifying DPoP (Demonstrating Proof-of-Possession) proofs.
 *
 * Implementations must:
 * - Check proof expiry (iat within clock skew tolerance)
 * - Track jti values to prevent replay attacks
 * - Verify the cryptographic signature (in infrastructure adapter)
 */
export interface DpopVerifier {
  /**
   * Verifies a DPoP proof's freshness and uniqueness.
   * @param proof The DPoP proof to verify
   * @param nowSeconds Current time in seconds since epoch
   * @param maxAgeSec Maximum allowed age for the proof's iat claim
   */
  verify(
    proof: DpopProof,
    nowSeconds: number,
    maxAgeSec: number,
  ): Promise<{ valid: boolean; error?: string }>;

  /**
   * Verifies that the DPoP proof's key thumbprint matches the expected
   * thumbprint from the token's cnf claim.
   */
  verifyThumbprintMatch(
    proof: DpopProof,
    expectedThumbprint: string,
  ): Promise<{ valid: boolean; error?: string }>;
}
