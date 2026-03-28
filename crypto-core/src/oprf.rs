// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Oblivious Pseudo-Random Function (OPRF) over Ristretto255.
//!
//! Implements the OPRF protocol (RFC 9497 / VOPRF) for vault key derivation.
//! The client blinds the password, the server evaluates blindly, the client unblinds.
//! Neither party learns the other's secret.
//!
//! Protocol:
//!   Client: P = hash_to_group(password), B = r·P (blind)
//!   Server: E = k·B (evaluate)
//!   Client: U = r⁻¹·E = k·P (unblind)
//!
//! Security: DDH assumption on Ristretto255.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;

use crate::errors::{CryptoError, CryptoResult};

/// Domain separation tag for the OPRF hash-to-group operation.
/// MUST differ from the Sigma protocol DST to prevent cross-protocol attacks.
pub const OPRF_DST: &str = "2FApi-OPRF-HashToGroup-v1";

/// Maps an arbitrary input to a Ristretto255 group element.
///
/// Uses SHA-512(DST || input) to produce 64 uniform bytes,
/// then maps to a Ristretto point via `from_uniform_bytes`.
/// Deterministic: same input always produces same point.
pub fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(OPRF_DST.as_bytes());
    hasher.update(input);
    let hash = hasher.finalize();
    let mut uniform = [0u8; 64];
    uniform.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&uniform)
}

/// Blinds a group element with a random scalar.
///
/// Returns (B, r) where B = r · P and r is a random non-zero scalar.
/// The blinding factor r must be kept secret by the client.
pub fn blind(point: &RistrettoPoint) -> (RistrettoPoint, Scalar) {
    use rand::RngCore;
    loop {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        let r = Scalar::from_bytes_mod_order_wide(&bytes);
        if r != Scalar::ZERO {
            let blinded = r * point;
            if blinded != RistrettoPoint::identity() {
                return (blinded, r);
            }
        }
    }
}

/// Server-side: evaluates the OPRF on a blinded element.
///
/// Computes E = k · B where k is the server's OPRF key.
/// The server never sees the password — only the blinded point B.
pub fn evaluate(blinded: &RistrettoPoint, oprf_key: &Scalar) -> CryptoResult<RistrettoPoint> {
    if *blinded == RistrettoPoint::identity() {
        return Err(CryptoError::IdentityPoint);
    }
    let evaluated = oprf_key * blinded;
    if evaluated == RistrettoPoint::identity() {
        return Err(CryptoError::IdentityPoint);
    }
    Ok(evaluated)
}

/// Client-side: unblinds the server's evaluation.
///
/// Computes U = r⁻¹ · E = k · P (the OPRF output).
/// The client never sees the OPRF key k.
pub fn unblind(evaluated: &RistrettoPoint, r: &Scalar) -> CryptoResult<RistrettoPoint> {
    if *r == Scalar::ZERO {
        return Err(CryptoError::InvalidScalarEncoding);
    }
    let r_inv = r.invert();
    Ok(r_inv * evaluated)
}

/// Generates a random non-zero OPRF key (server-side).
///
/// The key is a random scalar in the Ristretto255 group order.
pub fn generate_oprf_key() -> Scalar {
    use rand::RngCore;
    loop {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        let k = Scalar::from_bytes_mod_order_wide(&bytes);
        if k != Scalar::ZERO {
            return k;
        }
    }
}

/// Validates that 32 bytes are a canonical, non-identity Ristretto255 point.
///
/// Used by the server to reject invalid blinded points from clients.
pub fn validate_point(bytes: &[u8; 32]) -> CryptoResult<RistrettoPoint> {
    let compressed = CompressedRistretto::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidPointEncoding)?;
    let point = compressed.decompress()
        .ok_or(CryptoError::InvalidPointEncoding)?;
    if point == RistrettoPoint::identity() {
        return Err(CryptoError::IdentityPoint);
    }
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Scenario #47: Domain Separation ---

    #[test]
    fn oprf_dst_differs_from_sigma_dst() {
        let sigma_dst = "2FApi-v1.0-Sigma";
        assert_ne!(OPRF_DST, sigma_dst);
        assert!(OPRF_DST.starts_with("2FApi-OPRF-"));
    }

    // --- Scenario #47: hash_to_group ---

    #[test]
    fn hash_to_group_produces_non_identity_point() {
        let point = hash_to_group(b"blue tiger fast moon");
        assert_ne!(point, RistrettoPoint::identity());
    }

    #[test]
    fn hash_to_group_is_deterministic() {
        let p1 = hash_to_group(b"blue tiger fast moon");
        let p2 = hash_to_group(b"blue tiger fast moon");
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_to_group_different_inputs_produce_different_points() {
        let p1 = hash_to_group(b"blue tiger fast moon");
        let p2 = hash_to_group(b"red ocean calm star");
        assert_ne!(p1, p2);
    }

    // --- Scenario #1a: Client blinding ---

    #[test]
    fn blind_returns_valid_point_and_nonzero_scalar() {
        let point = hash_to_group(b"test password");
        let (blinded, r) = blind(&point);
        assert_ne!(blinded, RistrettoPoint::identity());
        assert_ne!(r, Scalar::ZERO);
    }

    // --- Scenario #4: ZK property (blinding hides input) ---

    #[test]
    fn two_blindings_of_same_point_produce_different_blinded_elements() {
        let point = hash_to_group(b"same password");
        let (b1, _) = blind(&point);
        let (b2, _) = blind(&point);
        assert_ne!(b1, b2);
    }

    // --- Scenario #35: OPRF key generation ---

    #[test]
    fn generate_oprf_key_is_nonzero() {
        let k = generate_oprf_key();
        assert_ne!(k, Scalar::ZERO);
    }

    #[test]
    fn generate_oprf_key_produces_different_keys() {
        let k1 = generate_oprf_key();
        let k2 = generate_oprf_key();
        assert_ne!(k1, k2);
    }

    // --- Scenario #36: Server evaluation ---

    #[test]
    fn evaluate_returns_valid_non_identity_point() {
        let point = hash_to_group(b"password");
        let (blinded, _) = blind(&point);
        let k = generate_oprf_key();
        let evaluated = evaluate(&blinded, &k).unwrap();
        assert_ne!(evaluated, RistrettoPoint::identity());
    }

    // --- Scenario #1b: Full OPRF correctness ---

    #[test]
    fn unblind_evaluate_blind_equals_k_times_point() {
        let password = b"blue tiger fast moon";
        let p = hash_to_group(password);
        let k = generate_oprf_key();

        // Client blinds
        let (blinded, r) = blind(&p);

        // Server evaluates
        let evaluated = evaluate(&blinded, &k).unwrap();

        // Client unblinds
        let u = unblind(&evaluated, &r).unwrap();

        // Expected: U = k · P
        let expected = k * p;
        assert_eq!(u, expected);
    }

    // --- Scenario #2+3: Determinism ---

    #[test]
    fn same_password_same_key_produces_same_oprf_output() {
        let password = b"MyD3v!ceP@ss";
        let p = hash_to_group(password);
        let k = generate_oprf_key();

        let (b1, r1) = blind(&p);
        let e1 = evaluate(&b1, &k).unwrap();
        let u1 = unblind(&e1, &r1).unwrap();

        let (b2, r2) = blind(&p);
        let e2 = evaluate(&b2, &k).unwrap();
        let u2 = unblind(&e2, &r2).unwrap();

        assert_eq!(u1, u2, "same password must produce same OPRF output");
    }

    #[test]
    fn different_passwords_produce_different_oprf_outputs() {
        let k = generate_oprf_key();

        let p1 = hash_to_group(b"MyD3v!ceP@ss");
        let (b1, r1) = blind(&p1);
        let e1 = evaluate(&b1, &k).unwrap();
        let u1 = unblind(&e1, &r1).unwrap();

        let p2 = hash_to_group(b"WrongP@ss!");
        let (b2, r2) = blind(&p2);
        let e2 = evaluate(&b2, &k).unwrap();
        let u2 = unblind(&e2, &r2).unwrap();

        assert_ne!(u1, u2, "different passwords must produce different outputs");
    }

    // --- Scenario #5: Anti-replay ---

    #[test]
    fn replayed_evaluation_unblinds_to_wrong_value() {
        let password = b"MyD3v!ceP@ss";
        let p = hash_to_group(password);
        let k = generate_oprf_key();

        // First OPRF (legitimate)
        let (b1, r1) = blind(&p);
        let e1 = evaluate(&b1, &k).unwrap();
        let u_correct = unblind(&e1, &r1).unwrap();

        // Second OPRF (new blinding)
        let (_b2, r2) = blind(&p);

        // Eve replays e1 instead of the real e2
        let u_replayed = unblind(&e1, &r2).unwrap();

        // The replayed unblinding produces a WRONG output
        assert_ne!(u_replayed, u_correct, "replayed evaluation must unblind to wrong value");
    }

    // --- Scenario #8+9: Validation ---

    #[test]
    fn evaluate_rejects_identity_point() {
        let identity = RistrettoPoint::identity();
        let k = generate_oprf_key();
        assert!(evaluate(&identity, &k).is_err());
    }

    #[test]
    fn validate_point_rejects_non_canonical_bytes() {
        let bad_bytes = [0xFF; 32];
        assert!(validate_point(&bad_bytes).is_err());
    }

    #[test]
    fn validate_point_rejects_identity() {
        let identity_bytes = RistrettoPoint::identity().compress().to_bytes();
        assert!(validate_point(&identity_bytes).is_err());
    }

    #[test]
    fn validate_point_accepts_valid_non_identity() {
        let point = hash_to_group(b"test");
        let bytes = point.compress().to_bytes();
        let validated = validate_point(&bytes).unwrap();
        assert_eq!(validated, point);
    }

    #[test]
    fn unblind_rejects_zero_blinding() {
        let point = hash_to_group(b"test");
        assert!(unblind(&point, &Scalar::ZERO).is_err());
    }
}
