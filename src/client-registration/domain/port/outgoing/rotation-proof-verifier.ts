// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Commitment } from "../../model/commitment.js";

/**
 * Verifies the cryptographic proofs required for commitment rotation:
 * 1. Proof of knowledge of the current commitment opening (s, r)
 * 2. Proof of possession of the new commitment opening
 *
 * Implementation requirements:
 * - MUST execute in constant time regardless of proof validity
 * - MUST NOT short-circuit on intermediate comparison failures
 */
export interface RotationProofVerifier {
  /**
   * Verifies both the proof of current commitment knowledge
   * and the proof of possession for the new commitment.
   *
   * @param currentCommitment - The client's current stored commitment
   * @param currentProofBytes - Schnorr proof for the current commitment
   * @param newCommitment - The proposed new commitment
   * @param newProofBytes - Proof of possession for the new commitment
   * @returns true if both proofs are valid
   */
  verify(
    currentCommitment: Commitment,
    currentProofBytes: Uint8Array,
    newCommitment: Commitment,
    newProofBytes: Uint8Array,
  ): boolean;
}
