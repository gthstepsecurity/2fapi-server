// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Client enrollment domain logic.
//!
//! Pure business rules — no PostgreSQL dependency.

use twofapi_crypto_core as crypto;

/// Result of an enrollment attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollmentResult {
    /// Client enrolled successfully.
    Success { client_id: String },
    /// Commitment is not a valid Ristretto255 point.
    InvalidCommitment(String),
    /// Commitment is the identity element (forbidden).
    IdentityCommitment,
    /// Proof of possession is invalid.
    InvalidProof,
    /// Client already exists (indistinguishable from success for anti-enumeration).
    AlreadyExists,
}

/// Validates a commitment for enrollment.
///
/// Checks:
/// - Exactly 32 bytes
/// - Valid canonical Ristretto255 encoding
/// - Not the identity element
pub fn validate_commitment(commitment: &[u8]) -> Result<(), EnrollmentResult> {
    if commitment.len() != 32 {
        return Err(EnrollmentResult::InvalidCommitment(format!(
            "Expected 32 bytes, got {}",
            commitment.len()
        )));
    }

    if !crypto::is_canonical_point_slice(commitment) {
        return Err(EnrollmentResult::InvalidCommitment(
            "Not a canonical Ristretto255 encoding".into(),
        ));
    }

    if crypto::is_identity_slice(commitment) {
        return Err(EnrollmentResult::IdentityCommitment);
    }

    Ok(())
}

/// Validates a proof of possession for enrollment.
///
/// The proof must be exactly 96 bytes (announcement + 2 response scalars).
pub fn validate_proof_of_possession(proof: &[u8]) -> Result<(), EnrollmentResult> {
    if proof.len() != 96 {
        return Err(EnrollmentResult::InvalidProof);
    }

    let announcement = &proof[0..32];
    let response_s = &proof[32..64];
    let response_r = &proof[64..96];

    // Validate announcement is a canonical point and not identity
    if !crypto::is_canonical_point_slice(announcement) || crypto::is_identity_slice(announcement) {
        return Err(EnrollmentResult::InvalidProof);
    }

    // Validate response scalars are canonical
    if !crypto::is_canonical_scalar_slice(response_s) || !crypto::is_canonical_scalar_slice(response_r) {
        return Err(EnrollmentResult::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_commitment_wrong_length() {
        let short = vec![0u8; 31];
        assert!(matches!(
            validate_commitment(&short),
            Err(EnrollmentResult::InvalidCommitment(_))
        ));
    }

    #[test]
    fn rejects_identity_commitment() {
        let identity = vec![0u8; 32];
        assert!(matches!(
            validate_commitment(&identity),
            Err(EnrollmentResult::IdentityCommitment)
        ));
    }

    #[test]
    fn accepts_valid_commitment() {
        // Use a real Ristretto255 point (the basepoint compressed)
        let g = crypto::generator_g().compress().to_bytes();
        assert!(validate_commitment(&g).is_ok());
    }

    #[test]
    fn rejects_proof_wrong_length() {
        let short = vec![0u8; 95];
        assert!(matches!(
            validate_proof_of_possession(&short),
            Err(EnrollmentResult::InvalidProof)
        ));
    }

    #[test]
    fn rejects_proof_with_identity_announcement() {
        let mut proof = vec![0u8; 96]; // identity announcement
        // Even with valid scalars, identity announcement is rejected
        assert!(matches!(
            validate_proof_of_possession(&proof),
            Err(EnrollmentResult::InvalidProof)
        ));
    }
}
