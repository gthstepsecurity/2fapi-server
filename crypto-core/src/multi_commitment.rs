// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Multi-commitment verification for multi-device authentication.
//!
//! When a user has N devices, the server stores N commitments.
//! Authentication succeeds if the proof matches ANY active commitment.
//!
//! Security: verification is constant-time across all commitments
//! to prevent timing oracles that reveal the number of enrolled devices.

/// Verifies a proof against a list of commitments.
///
/// Returns the index of the matching commitment, or None if no match.
///
/// SECURITY: All commitments are checked regardless of early matches
/// to ensure constant-time behavior (no timing oracle on device count).
pub fn verify_any_commitment(
    commitments: &[&[u8]],   // List of 32-byte commitments
    proof: &[u8],             // 96-byte proof
    client_id: &str,
    nonce: &[u8],
    channel_binding: &[u8],
) -> Option<usize> {
    if commitments.is_empty() {
        return None;
    }

    let (g, h) = crate::generators();
    let g_bytes = g.compress().to_bytes();
    let h_bytes = h.compress().to_bytes();

    if proof.len() != 96 {
        return None;
    }

    let announcement = &proof[0..32];
    let response_s = &proof[32..64];
    let response_r = &proof[64..96];

    let mut matched_index: Option<usize> = None;

    // Check ALL commitments (constant number of iterations)
    for (i, commitment) in commitments.iter().enumerate() {
        if commitment.len() != 32 {
            continue;
        }

        // Build transcript for this commitment
        let transcript_bytes = build_canonical_transcript(
            &g_bytes,
            &h_bytes,
            commitment,
            announcement,
            client_id.as_bytes(),
            nonce,
            channel_binding,
        );

        let challenge = crate::hash_transcript_bytes(&transcript_bytes);

        // Verify equation
        let valid = crate::verify_equation_raw(
            &g_bytes,
            &h_bytes,
            commitment,
            announcement,
            &challenge,
            response_s,
            response_r,
        );

        if valid && matched_index.is_none() {
            matched_index = Some(i);
        }
        // Continue checking even after a match (constant-time)
    }

    matched_index
}

/// Builds a transcript for multi-commitment verification.
/// This is the same format as domain/transcript.rs in the extensions.
fn bip39_transcript_internal(
    tag: &[u8],
    generator_g: &[u8],
    generator_h: &[u8],
    commitment: &[u8],
    announcement: &[u8],
    client_id: &[u8],
    nonce: &[u8],
    channel_binding: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::new();
    write_field(&mut transcript, tag);
    write_field(&mut transcript, generator_g);
    write_field(&mut transcript, generator_h);
    write_field(&mut transcript, commitment);
    write_field(&mut transcript, announcement);
    write_field(&mut transcript, client_id);
    write_field(&mut transcript, nonce);
    write_field(&mut transcript, channel_binding);
    transcript
}

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Protocol tag for 2FApi Sigma transcripts.
const PROTOCOL_TAG: &[u8] = b"2FApi-v1.0-Sigma";

/// Public transcript builder matching the canonical format.
pub fn build_canonical_transcript(
    generator_g: &[u8],
    generator_h: &[u8],
    commitment: &[u8],
    announcement: &[u8],
    client_id: &[u8],
    nonce: &[u8],
    channel_binding: &[u8],
) -> Vec<u8> {
    bip39_transcript_internal(
        PROTOCOL_TAG,
        generator_g,
        generator_h,
        commitment,
        announcement,
        client_id,
        nonce,
        channel_binding,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    use rand::RngCore;

    fn make_enrolled_device() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let (g, h) = crate::generators();
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let secret = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let blinding = Scalar::from_bytes_mod_order_wide(&wide);
        let commitment = RistrettoPoint::vartime_multiscalar_mul(
            [&secret, &blinding], [g, h],
        );
        (secret.to_bytes(), blinding.to_bytes(), commitment.compress().to_bytes())
    }

    fn make_proof(secret: &[u8; 32], blinding: &[u8; 32], commitment: &[u8; 32], client_id: &str, nonce: &[u8]) -> [u8; 96] {
        let (g, h) = crate::generators();
        let g_bytes = g.compress().to_bytes();
        let h_bytes = h.compress().to_bytes();

        let s = Scalar::from_canonical_bytes(*secret).unwrap();
        let r = Scalar::from_canonical_bytes(*blinding).unwrap();

        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_s = Scalar::from_bytes_mod_order_wide(&wide);
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let k_r = Scalar::from_bytes_mod_order_wide(&wide);

        let announcement = RistrettoPoint::vartime_multiscalar_mul([&k_s, &k_r], [g, h]);
        let announcement_bytes = announcement.compress().to_bytes();

        let transcript = build_canonical_transcript(
            &g_bytes, &h_bytes, commitment, &announcement_bytes,
            client_id.as_bytes(), nonce, &[],
        );
        let challenge_bytes = crate::hash_transcript_bytes(&transcript);
        let challenge = Scalar::from_canonical_bytes({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&challenge_bytes);
            arr
        }).unwrap();

        let z_s = k_s + challenge * s;
        let z_r = k_r + challenge * r;

        let mut proof = [0u8; 96];
        proof[0..32].copy_from_slice(&announcement_bytes);
        proof[32..64].copy_from_slice(&z_s.to_bytes());
        proof[64..96].copy_from_slice(&z_r.to_bytes());
        proof
    }

    #[test]
    fn single_commitment_matches() {
        let (s, r, c) = make_enrolled_device();
        let proof = make_proof(&s, &r, &c, "alice", &[0xABu8; 16]);
        let result = verify_any_commitment(&[&c], &proof, "alice", &[0xABu8; 16], &[]);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn second_commitment_matches() {
        let (_, _, c1) = make_enrolled_device(); // different device
        let (s2, r2, c2) = make_enrolled_device();
        let proof = make_proof(&s2, &r2, &c2, "alice", &[0xABu8; 16]);
        let result = verify_any_commitment(&[&c1, &c2], &proof, "alice", &[0xABu8; 16], &[]);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn no_commitment_matches() {
        let (_, _, c1) = make_enrolled_device();
        let (s2, r2, c2) = make_enrolled_device();
        // Proof for c2, but only c1 in the list
        let proof = make_proof(&s2, &r2, &c2, "alice", &[0xABu8; 16]);
        let result = verify_any_commitment(&[&c1], &proof, "alice", &[0xABu8; 16], &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn empty_commitment_list() {
        let (s, r, c) = make_enrolled_device();
        let proof = make_proof(&s, &r, &c, "alice", &[0xABu8; 16]);
        let result = verify_any_commitment(&[], &proof, "alice", &[0xABu8; 16], &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn three_devices_third_matches() {
        let (_, _, c1) = make_enrolled_device();
        let (_, _, c2) = make_enrolled_device();
        let (s3, r3, c3) = make_enrolled_device();
        let proof = make_proof(&s3, &r3, &c3, "alice", &[0xABu8; 16]);
        let result = verify_any_commitment(
            &[&c1, &c2, &c3], &proof, "alice", &[0xABu8; 16], &[],
        );
        assert_eq!(result, Some(2));
    }

    #[test]
    fn wrong_client_id_fails() {
        let (s, r, c) = make_enrolled_device();
        let proof = make_proof(&s, &r, &c, "alice", &[0xABu8; 16]);
        // Verify with different client_id
        let result = verify_any_commitment(&[&c], &proof, "bob", &[0xABu8; 16], &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn wrong_nonce_fails() {
        let (s, r, c) = make_enrolled_device();
        let proof = make_proof(&s, &r, &c, "alice", &[0xABu8; 16]);
        // Verify with different nonce
        let result = verify_any_commitment(&[&c], &proof, "alice", &[0xCDu8; 16], &[]);
        assert_eq!(result, None);
    }
}
