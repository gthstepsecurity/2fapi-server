// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! 2FApi Cryptographic Core
//!
//! Implements the cryptographic primitives for the 2FApi zero-knowledge
//! proof authentication protocol:
//!
//! - **Pedersen commitments** over Ristretto255: C = s·G + r·H
//! - **Sigma proofs**: non-interactive proofs of knowledge of (s, r) opening C
//! - **Fiat-Shamir transcript**: domain-separated challenge derivation
//! - **Element validation**: canonical encoding checks for points and scalars
//!
//! # Security properties
//! - All operations on secret data are constant-time (via `subtle` crate)
//! - Secret scalars derive `Zeroize` and `ZeroizeOnDrop`
//! - No `unsafe` code
//! - No panics in library code (all errors via `Result`)

pub mod errors;
pub mod generators;
pub mod pedersen;
pub mod sigma;
pub mod transcript;
pub mod bip39;
pub mod derivation;
pub mod multi_commitment;
pub mod oprf;
pub mod sharing;

// Re-export commonly used types at the crate root.
pub use errors::{CryptoError, CryptoResult};
pub use pedersen::{commit, commit_with_generators, decode_scalar, decompress_point, verify_commitment};
pub use sigma::{prove, verify, verify_equation, Proof, ProofRandomness};
pub use transcript::{hash_transcript, hash_transcript_bytes};
pub use generators::{generator_g, generator_h, generators};
pub use derivation::{derive_credential, derive_credential_with_pepper, derive_credential_with_oprf, validate_passphrase, validate_pin, DerivedCredential};
pub use bip39::{chained_hash, chained_hash_from_words};
pub use multi_commitment::{verify_any_commitment, build_canonical_transcript};
pub use sharing::{
    split_into_shares, partial_commitment, client_partial_response,
    server_partial_response, combine_responses, SecretShare, PartialResponse,
};
pub use oprf::{
    OPRF_DST, hash_to_group, blind, evaluate as oprf_evaluate,
    unblind, generate_oprf_key, validate_point,
};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::ristretto::RistrettoPoint;
use subtle::ConstantTimeEq;

/// Checks whether the given 32 bytes are a canonical Ristretto255 point encoding.
///
/// A canonical encoding must decompress successfully. This does NOT check
/// for the identity element (use `is_identity` separately).
pub fn is_canonical_point(bytes: &[u8; 32]) -> bool {
    CompressedRistretto::from_slice(bytes)
        .ok()
        .and_then(|c| c.decompress())
        .is_some()
}

/// Checks whether the given 32 bytes are a canonical scalar encoding
/// (i.e., reduced modulo the group order l).
pub fn is_canonical_scalar(bytes: &[u8; 32]) -> bool {
    bool::from(Scalar::from_canonical_bytes(*bytes).is_some())
}

/// Checks whether the given 32 bytes encode the identity (neutral) element.
///
/// The identity in Ristretto255 compressed form is 32 zero bytes.
pub fn is_identity(bytes: &[u8; 32]) -> bool {
    let identity_bytes = RistrettoPoint::identity().compress().to_bytes();
    bool::from(bytes.ct_eq(&identity_bytes))
}

// --- Slice-accepting wrappers for extensions (pg_2fapi, redis-2fapi) ---

/// Like `is_canonical_point` but accepts a dynamic slice.
/// Returns false if the slice is not exactly 32 bytes.
pub fn is_canonical_point_slice(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    is_canonical_point(&arr)
}

/// Like `is_canonical_scalar` but accepts a dynamic slice.
pub fn is_canonical_scalar_slice(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    is_canonical_scalar(&arr)
}

/// Like `is_identity` but accepts a dynamic slice.
pub fn is_identity_slice(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    is_identity(&arr)
}

/// Verifies the Sigma equation from raw byte slices.
///
/// z_s·G + z_r·H == A + c·C
///
/// All inputs are 32-byte slices. Returns false on any decoding failure.
pub fn verify_equation_raw(
    generator_g: &[u8],
    generator_h: &[u8],
    commitment: &[u8],
    announcement: &[u8],
    challenge: &[u8],
    response_s: &[u8],
    response_r: &[u8],
) -> bool {
    use curve25519_dalek::ristretto::RistrettoPoint;

    let decode_point = |bytes: &[u8]| -> Option<RistrettoPoint> {
        if bytes.len() != 32 { return None; }
        CompressedRistretto::from_slice(bytes).ok()?.decompress()
    };
    let decode_scalar = |bytes: &[u8]| -> Option<Scalar> {
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Scalar::from_canonical_bytes(arr).into()
    };

    let g = match decode_point(generator_g) { Some(p) => p, None => return false };
    let h = match decode_point(generator_h) { Some(p) => p, None => return false };
    let c_point = match decode_point(commitment) { Some(p) => p, None => return false };
    let a = match decode_point(announcement) { Some(p) => p, None => return false };
    let c_scalar = match decode_scalar(challenge) { Some(s) => s, None => return false };
    let z_s = match decode_scalar(response_s) { Some(s) => s, None => return false };
    let z_r = match decode_scalar(response_r) { Some(s) => s, None => return false };

    // Reject zero challenge
    if c_scalar == Scalar::ZERO {
        return false;
    }

    // Reject identity announcement
    if a == RistrettoPoint::identity() {
        return false;
    }

    // Reject identity commitment
    if c_point == RistrettoPoint::identity() {
        return false;
    }

    // Reject zero response scalars (defense-in-depth).
    // FIX A-001: Reject if EITHER z_s or z_r is zero (not just both).
    // While Fiat-Shamir prevents circular construction when one is zero,
    // legitimate proofs never have zero responses — rejecting is safe.
    if z_s == Scalar::ZERO || z_r == Scalar::ZERO {
        return false;
    }

    // Verify: z_s·G + z_r·H == A + c·C
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    let lhs = RistrettoPoint::vartime_multiscalar_mul(&[z_s, z_r], &[g, h]);
    let rhs = a + c_scalar * c_point;

    let lhs_bytes = lhs.compress().to_bytes();
    let rhs_bytes = rhs.compress().to_bytes();
    bool::from(lhs_bytes.ct_eq(&rhs_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_bytes_are_all_zeros() {
        let identity = RistrettoPoint::identity().compress().to_bytes();
        assert!(identity.iter().all(|&b| b == 0));
    }

    #[test]
    fn is_identity_detects_identity() {
        let identity = RistrettoPoint::identity().compress().to_bytes();
        assert!(is_identity(&identity));
    }

    #[test]
    fn is_identity_rejects_non_identity() {
        let g = generators::generator_g().compress().to_bytes();
        assert!(!is_identity(&g));
    }

    #[test]
    fn is_canonical_point_accepts_valid_point() {
        let g = generators::generator_g().compress().to_bytes();
        assert!(is_canonical_point(&g));
    }

    #[test]
    fn is_canonical_point_rejects_invalid_bytes() {
        let bad = [0xffu8; 32];
        assert!(!is_canonical_point(&bad));
    }

    #[test]
    fn is_canonical_scalar_accepts_zero() {
        let zero = Scalar::ZERO.to_bytes();
        assert!(is_canonical_scalar(&zero));
    }

    #[test]
    fn is_canonical_scalar_accepts_one() {
        let one = Scalar::ONE.to_bytes();
        assert!(is_canonical_scalar(&one));
    }

    #[test]
    fn is_canonical_scalar_rejects_unreduced() {
        let bytes = [0xffu8; 32];
        assert!(!is_canonical_scalar(&bytes));
    }

    // --- Mutation testing killers for slice wrappers ---

    #[test]
    fn is_canonical_point_slice_accepts_valid_point() {
        let g = generators::generator_g().compress().to_bytes();
        assert!(is_canonical_point_slice(&g));
    }

    #[test]
    fn is_canonical_point_slice_rejects_wrong_length() {
        assert!(!is_canonical_point_slice(&[0u8; 16]));
        assert!(!is_canonical_point_slice(&[0u8; 33]));
    }

    #[test]
    fn is_canonical_point_slice_rejects_invalid() {
        assert!(!is_canonical_point_slice(&[0xFFu8; 32]));
    }

    #[test]
    fn is_canonical_scalar_slice_accepts_valid() {
        let one = Scalar::ONE.to_bytes();
        assert!(is_canonical_scalar_slice(&one));
    }

    #[test]
    fn is_canonical_scalar_slice_rejects_wrong_length() {
        assert!(!is_canonical_scalar_slice(&[0u8; 16]));
    }

    #[test]
    fn is_canonical_scalar_slice_rejects_unreduced() {
        assert!(!is_canonical_scalar_slice(&[0xFFu8; 32]));
    }

    #[test]
    fn is_identity_slice_detects_identity() {
        let id = RistrettoPoint::identity().compress().to_bytes();
        assert!(is_identity_slice(&id));
    }

    #[test]
    fn is_identity_slice_rejects_non_identity() {
        let g = generators::generator_g().compress().to_bytes();
        assert!(!is_identity_slice(&g));
    }

    #[test]
    fn is_identity_slice_rejects_wrong_length() {
        assert!(!is_identity_slice(&[0u8; 16]));
    }

    #[test]
    fn verify_equation_raw_rejects_zero_responses() {
        let (g, h) = generators::generators();
        let gb = g.compress().to_bytes();
        let hb = h.compress().to_bytes();
        let s = Scalar::ONE;
        let r = Scalar::ONE;
        let c = pedersen::commit(&s, &r);
        let cb = c.compress().to_bytes();
        let ab = (Scalar::from(2u64) * g + Scalar::from(3u64) * h).compress().to_bytes();
        let challenge = Scalar::ONE.to_bytes();
        let zero = Scalar::ZERO.to_bytes();
        let nonzero = Scalar::ONE.to_bytes();

        // z_s = 0 → must reject
        assert!(!verify_equation_raw(&gb, &hb, &cb, &ab, &challenge, &zero, &nonzero));
        // z_r = 0 → must reject
        assert!(!verify_equation_raw(&gb, &hb, &cb, &ab, &challenge, &nonzero, &zero));
        // both zero → must reject
        assert!(!verify_equation_raw(&gb, &hb, &cb, &ab, &challenge, &zero, &zero));
    }
}
