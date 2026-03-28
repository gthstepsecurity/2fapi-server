// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Hash-to-point generation for the Pedersen commitment generators G and H.
//!
//! G is the Ristretto255 basepoint.
//! H is derived via hash-to-point from a domain-separated seed to ensure
//! that no one knows the discrete log relationship between G and H.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

/// Domain separation tag for deriving generator H.
const GENERATOR_H_DST: &[u8] = b"2FApi-Pedersen-GeneratorH-v1";

/// Returns the primary generator G (the Ristretto255 basepoint).
pub fn generator_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// Returns the secondary generator H, derived via hash-to-point.
///
/// H is derived by hashing the DST with SHA-512 to produce 64 uniform bytes,
/// then mapping to a Ristretto point via `from_uniform_bytes`.
///
/// This ensures that the discrete log of H with respect to G is unknown,
/// which is required for the binding property of Pedersen commitments.
pub fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(GENERATOR_H_DST);
    let hash_output = hasher.finalize();
    let mut uniform_bytes = [0u8; 64];
    uniform_bytes.copy_from_slice(&hash_output);
    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}

/// Returns both generators (G, H) as a tuple.
pub fn generators() -> (RistrettoPoint, RistrettoPoint) {
    (generator_g(), generator_h())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn generator_g_is_not_identity() {
        assert_ne!(generator_g(), RistrettoPoint::identity());
    }

    #[test]
    fn generator_h_is_not_identity() {
        assert_ne!(generator_h(), RistrettoPoint::identity());
    }

    #[test]
    fn generators_are_distinct() {
        assert_ne!(generator_g(), generator_h());
    }

    #[test]
    fn generators_are_deterministic() {
        let (g1, h1) = generators();
        let (g2, h2) = generators();
        assert_eq!(g1, g2);
        assert_eq!(h1, h2);
    }
}
