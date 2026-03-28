// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Commitment } from "../../model/commitment.js";

export interface ProofOfPossessionData {
  announcement: Uint8Array;
  responseS: Uint8Array;
  responseR: Uint8Array;
}

/**
 * Verifies a Schnorr-like proof of possession for a Pedersen commitment.
 *
 * The Fiat-Shamir challenge MUST be computed over the transcript:
 *   challenge = H(domain_tag || g || h || commitment || announcement || clientIdentifier)
 *
 * This binds the proof to the specific commitment, generators, and client identity,
 * preventing proof replay and cross-context forgery.
 *
 * Implementation requirements:
 * - MUST execute in constant time regardless of proof validity.
 * - MUST NOT short-circuit on intermediate comparison failures.
 */
export interface ProofOfPossessionVerifier {
  /** Verifies proof of knowledge of (s, r) such that C = g^s * h^r.
   *  MUST execute in constant time regardless of validity. */
  verify(
    commitment: Commitment,
    proof: ProofOfPossessionData,
    clientIdentifier: string,
  ): boolean;
}
