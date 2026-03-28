// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Verifies cryptographic properties of a Pedersen commitment.
 *
 * Pipeline order: methods MUST be called in the following sequence:
 * 1. isCanonical — checks encoding validity
 * 2. isValidGroupElement — checks group membership
 * 3. isIdentityElement — rejects the neutral element
 *
 * Each method has the precondition that all previous checks passed.
 */
export interface CommitmentVerifier {
  /** Checks whether the byte encoding is canonical (reduced modulo p).
   *  Precondition: none (first in pipeline). */
  isCanonical(bytes: Uint8Array): boolean;

  /** Checks whether the bytes decode to a valid Ristretto255 group element.
   *  Precondition: isCanonical(bytes) === true. */
  isValidGroupElement(bytes: Uint8Array): boolean;

  /** Checks whether the element is the identity (neutral) element.
   *  Precondition: isValidGroupElement(bytes) === true. */
  isIdentityElement(bytes: Uint8Array): boolean;
}
