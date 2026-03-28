// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Proof verification domain logic.
//!
//! Verifies Sigma proofs against stored Pedersen commitments.

use twofapi_crypto_core as crypto;
use crate::domain::transcript;

/// Result of a proof verification attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationResult {
    /// Proof is valid.
    Valid,
    /// Proof is invalid (indistinguishable reason).
    Invalid,
    /// Challenge not found or expired.
    ChallengeNotFound,
    /// Client not found or not active.
    ClientNotFound,
}

/// Validates the encoding of proof bytes before cryptographic verification.
///
/// Checks:
/// - Exactly 96 bytes
/// - Announcement is canonical and not identity
/// - Response scalars are canonical
pub fn validate_proof_encoding(proof: &[u8]) -> Result<(), VerificationResult> {
    if proof.len() != 96 {
        return Err(VerificationResult::Invalid);
    }

    let announcement = &proof[0..32];
    let response_s = &proof[32..64];
    let response_r = &proof[64..96];

    if !crypto::is_canonical_point_slice(announcement) {
        return Err(VerificationResult::Invalid);
    }

    if crypto::is_identity_slice(announcement) {
        return Err(VerificationResult::Invalid);
    }

    if !crypto::is_canonical_scalar_slice(response_s) {
        return Err(VerificationResult::Invalid);
    }

    if !crypto::is_canonical_scalar_slice(response_r) {
        return Err(VerificationResult::Invalid);
    }

    Ok(())
}

/// Verifies a Sigma proof against a commitment using the canonical transcript.
///
/// This function:
/// 1. Validates proof encoding
/// 2. Builds the Fiat-Shamir transcript (length-prefixed, matching TypeScript format)
/// 3. Computes the challenge scalar c = H(transcript)
/// 4. Verifies the equation: z_s·G + z_r·H == A + c·C
///
/// Returns `VerificationResult::Valid` if and only if all checks pass.
pub fn verify_proof(
    commitment: &[u8],
    proof: &[u8],
    client_id: &str,
    nonce: &[u8],
    channel_binding: &[u8],
) -> VerificationResult {
    // 1. Validate encoding
    if let Err(e) = validate_proof_encoding(proof) {
        return e;
    }

    // 2. Validate commitment
    if !crypto::is_canonical_point_slice(commitment) || crypto::is_identity_slice(commitment) {
        return VerificationResult::ClientNotFound;
    }

    let announcement = &proof[0..32];
    let response_s = &proof[32..64];
    let response_r = &proof[64..96];

    // 3. Build transcript
    let (g, h) = crypto::generators();
    let g_bytes = g.compress().to_bytes();
    let h_bytes = h.compress().to_bytes();

    let transcript_bytes = transcript::build_transcript(
        transcript::PROTOCOL_TAG,
        &g_bytes,
        &h_bytes,
        commitment,
        announcement,
        client_id.as_bytes(),
        nonce,
        channel_binding,
    );

    // 4. Compute challenge
    let challenge = crypto::hash_transcript_bytes(&transcript_bytes);

    // 5. Reject zero challenge (defense-in-depth)
    if challenge.iter().all(|&b| b == 0) {
        return VerificationResult::Invalid;
    }

    // 6. Verify equation
    let valid = crypto::verify_equation_raw(
        &g_bytes, &h_bytes, commitment, announcement,
        &challenge, response_s, response_r,
    );

    if valid {
        VerificationResult::Valid
    } else {
        VerificationResult::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_proof_wrong_length() {
        let result = validate_proof_encoding(&[0u8; 95]);
        assert_eq!(result, Err(VerificationResult::Invalid));
    }

    #[test]
    fn rejects_proof_identity_announcement() {
        let mut proof = vec![0u8; 96]; // all zeros = identity announcement
        let result = validate_proof_encoding(&proof);
        assert_eq!(result, Err(VerificationResult::Invalid));
    }

    #[test]
    fn rejects_identity_commitment() {
        let commitment = [0u8; 32]; // identity
        let proof = [0x42u8; 96]; // arbitrary (won't reach equation check)
        let result = verify_proof(&commitment, &proof, "alice", &[0u8; 16], &[]);
        // Will fail at encoding validation or commitment check
        assert_ne!(result, VerificationResult::Valid);
    }

    #[test]
    fn rejects_random_bytes_as_proof() {
        let g = crypto::generator_g().compress().to_bytes();
        let random_proof = [0x42u8; 96]; // not a valid proof
        let result = verify_proof(&g, &random_proof, "alice", &[0u8; 16], &[]);
        // Random bytes won't form a valid proof
        assert_ne!(result, VerificationResult::Valid);
    }

    // --- Hardening tests (sprint-20) ---

    /// Helper: builds a structurally valid 96-byte proof from real crypto primitives.
    /// The proof consists of: announcement (32 bytes) || response_s (32 bytes) || response_r (32 bytes).
    /// All components are canonical encodings.
    fn make_canonical_proof_bytes() -> ([u8; 96], [u8; 32]) {
        use curve25519_dalek::scalar::Scalar;
        use rand::RngCore;

        let (g, h) = crypto::generators();

        // Generate random secret and blinding
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let secret = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let blinding = Scalar::from_bytes_mod_order_wide(&wide);

        // Commitment
        use curve25519_dalek::traits::VartimeMultiscalarMul;
        use curve25519_dalek::ristretto::RistrettoPoint;
        let commitment = RistrettoPoint::vartime_multiscalar_mul(
            [&secret, &blinding], [g, h],
        );
        let commitment_bytes = commitment.compress().to_bytes();

        // Random announcement scalars
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_s = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_r = Scalar::from_bytes_mod_order_wide(&wide);

        // Announcement
        let announcement = RistrettoPoint::vartime_multiscalar_mul(
            [&k_s, &k_r], [g, h],
        );
        let announcement_bytes = announcement.compress().to_bytes();

        // Build the transcript as verify_proof does internally
        let g_bytes = g.compress().to_bytes();
        let h_bytes = h.compress().to_bytes();
        let transcript_bytes = transcript::build_transcript(
            transcript::PROTOCOL_TAG,
            &g_bytes,
            &h_bytes,
            &commitment_bytes,
            &announcement_bytes,
            b"test-client",
            &[0xABu8; 16],
            &[],
        );
        let challenge_bytes = crypto::hash_transcript_bytes(&transcript_bytes);

        // Decode challenge as scalar
        let challenge = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&challenge_bytes);
            // challenge_bytes is already a canonical scalar (output of hash_transcript_bytes)
            Scalar::from_canonical_bytes(arr)
                .expect("hash_transcript_bytes must return canonical scalar")
        };

        // Compute responses: z_s = k_s + c*s, z_r = k_r + c*r
        let z_s = k_s + challenge * secret;
        let z_r = k_r + challenge * blinding;

        let mut proof = [0u8; 96];
        proof[0..32].copy_from_slice(&announcement_bytes);
        proof[32..64].copy_from_slice(&z_s.to_bytes());
        proof[64..96].copy_from_slice(&z_r.to_bytes());

        (proof, commitment_bytes)
    }

    #[test]
    fn valid_constructed_proof_verifies() {
        let (proof, commitment) = make_canonical_proof_bytes();
        let result = verify_proof(&commitment, &proof, "test-client", &[0xABu8; 16], &[]);
        assert_eq!(result, VerificationResult::Valid, "Correctly constructed proof must verify");
    }

    #[test]
    fn proof_with_first_byte_flipped_is_rejected() {
        let (mut proof, commitment) = make_canonical_proof_bytes();
        proof[0] ^= 0x01; // flip first byte of announcement
        let result = verify_proof(&commitment, &proof, "test-client", &[0xABu8; 16], &[]);
        assert_ne!(result, VerificationResult::Valid, "Proof with first byte flipped must be rejected");
    }

    #[test]
    fn proof_with_last_byte_flipped_is_rejected() {
        let (mut proof, commitment) = make_canonical_proof_bytes();
        proof[95] ^= 0x01; // flip last byte of response_r
        let result = verify_proof(&commitment, &proof, "test-client", &[0xABu8; 16], &[]);
        assert_ne!(result, VerificationResult::Valid, "Proof with last byte flipped must be rejected");
    }

    #[test]
    fn commitment_with_non_canonical_encoding_is_rejected() {
        let non_canonical = [0xFFu8; 32]; // Not a valid Ristretto point

        // Build a proof with valid encoding so we reach the commitment check.
        // Announcement = G (valid point, not identity), responses = Scalar::ONE (canonical).
        let g = crypto::generator_g().compress().to_bytes();
        let one_scalar = {
            let mut s = [0u8; 32];
            s[0] = 1;
            s
        };
        let mut proof = [0u8; 96];
        proof[0..32].copy_from_slice(&g);
        proof[32..64].copy_from_slice(&one_scalar);
        proof[64..96].copy_from_slice(&one_scalar);

        let result = verify_proof(&non_canonical, &proof, "alice", &[0u8; 16], &[]);
        assert_eq!(result, VerificationResult::ClientNotFound,
            "Non-canonical commitment must be rejected as ClientNotFound");
    }

    #[test]
    fn swapped_generators_cause_proof_failure() {
        // Build a valid proof, then verify that using it against a commitment
        // built with swapped generators fails. Since verify_proof uses the
        // canonical generator order (G, H) internally, a commitment built with
        // (H, G) instead will not match.
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::traits::VartimeMultiscalarMul;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use rand::RngCore;

        let (g, h) = crypto::generators();

        // Generate scalars
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let secret = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let blinding = Scalar::from_bytes_mod_order_wide(&wide);

        // Commitment with swapped generators: C' = s*H + r*G (instead of s*G + r*H)
        let swapped_commitment = RistrettoPoint::vartime_multiscalar_mul(
            [&secret, &blinding], [h, g], // H first, then G — swapped!
        );
        let swapped_bytes = swapped_commitment.compress().to_bytes();

        // Build proof against normal generators (honest prover with correct generators)
        let normal_commitment = RistrettoPoint::vartime_multiscalar_mul(
            [&secret, &blinding], [g, h],
        );

        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_s = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_r = Scalar::from_bytes_mod_order_wide(&wide);
        let announcement = RistrettoPoint::vartime_multiscalar_mul([&k_s, &k_r], [g, h]);
        let announcement_bytes = announcement.compress().to_bytes();

        // Build transcript against swapped commitment (what the verifier would do)
        let g_bytes = g.compress().to_bytes();
        let h_bytes = h.compress().to_bytes();
        let transcript_bytes = transcript::build_transcript(
            transcript::PROTOCOL_TAG,
            &g_bytes,
            &h_bytes,
            &swapped_bytes,
            &announcement_bytes,
            b"alice",
            &[0u8; 16],
            &[],
        );
        let challenge_bytes = crypto::hash_transcript_bytes(&transcript_bytes);
        let challenge = Scalar::from_canonical_bytes({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&challenge_bytes);
            arr
        }).expect("canonical");

        // Responses computed against normal generators + normal commitment
        // but the transcript used the swapped commitment
        let z_s = k_s + challenge * secret;
        let z_r = k_r + challenge * blinding;

        let mut proof = [0u8; 96];
        proof[0..32].copy_from_slice(&announcement_bytes);
        proof[32..64].copy_from_slice(&z_s.to_bytes());
        proof[64..96].copy_from_slice(&z_r.to_bytes());

        // Verify against swapped commitment — should fail
        let result = verify_proof(&swapped_bytes, &proof, "alice", &[0u8; 16], &[]);
        assert_ne!(result, VerificationResult::Valid,
            "Proof must fail when generators are effectively swapped (mismatched commitment)");
    }

    #[test]
    fn zero_length_nonce_produces_valid_transcript() {
        // Verifying with an empty nonce should not panic and should produce a
        // deterministic result (the proof will be invalid, but the transcript
        // construction must not crash).
        let g = crypto::generator_g().compress().to_bytes();
        let proof = [0x42u8; 96]; // arbitrary
        let result = verify_proof(&g, &proof, "alice", &[], &[]);
        // The proof is random garbage, so it won't verify,
        // but the important thing is no panic occurred.
        assert_ne!(result, VerificationResult::Valid);
    }
}
