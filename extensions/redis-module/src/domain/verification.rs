// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Proof verification for Redis module.
//!
//! Reuses the same Fiat-Shamir transcript format and verification equation
//! as the TypeScript server and the PostgreSQL extension.

use twofapi_crypto_core as crypto;

/// Verifies a Sigma proof against a commitment.
///
/// Same logic as pg_2fapi::domain::verification::verify_proof.
/// Builds length-prefixed Fiat-Shamir transcript, computes challenge,
/// and verifies the equation z_s·G + z_r·H == A + c·C.
/// Maximum nonce hex length (256 bytes decoded = 512 hex chars).
const MAX_NONCE_HEX_LEN: usize = 512;

pub fn verify_proof(
    commitment_hex: &str,
    proof_hex: &str,
    client_id: &str,
    nonce_hex: &str,
) -> bool {
    // FIX RD-028: Validate hex string lengths BEFORE decoding to prevent
    // memory allocation attacks (a 1GB hex string would allocate 500MB).
    if commitment_hex.len() != 64 {  // 32 bytes = 64 hex chars
        return false;
    }
    if proof_hex.len() != 192 {  // 96 bytes = 192 hex chars
        return false;
    }
    if nonce_hex.len() > MAX_NONCE_HEX_LEN {
        return false;
    }

    let commitment = match hex::decode(commitment_hex) {
        Ok(c) if c.len() == 32 => c,
        _ => return false,
    };
    let proof = match hex::decode(proof_hex) {
        Ok(p) if p.len() == 96 => p,
        _ => return false,
    };
    let nonce = match hex::decode(nonce_hex) {
        Ok(n) => n,
        _ => return false,
    };

    // Validate encodings
    if !crypto::is_canonical_point_slice(&commitment) || crypto::is_identity_slice(&commitment) {
        return false;
    }

    let announcement = &proof[0..32];
    let response_s = &proof[32..64];
    let response_r = &proof[64..96];

    if !crypto::is_canonical_point_slice(announcement) || crypto::is_identity_slice(announcement) {
        return false;
    }
    if !crypto::is_canonical_scalar_slice(response_s) || !crypto::is_canonical_scalar_slice(response_r) {
        return false;
    }

    // Build transcript (same format as TypeScript + PG extension)
    let (g, h) = crypto::generators();
    let g_bytes = g.compress().to_bytes();
    let h_bytes = h.compress().to_bytes();

    let tag = b"2FApi-v1.0-Sigma";
    let mut transcript = Vec::new();
    write_field(&mut transcript, tag);
    write_field(&mut transcript, &g_bytes);
    write_field(&mut transcript, &h_bytes);
    write_field(&mut transcript, &commitment);
    write_field(&mut transcript, announcement);
    write_field(&mut transcript, client_id.as_bytes());
    write_field(&mut transcript, &nonce);
    write_field(&mut transcript, &[]); // No channel binding in Redis (no TLS exporter)

    let challenge = crypto::hash_transcript_bytes(&transcript);

    // Reject zero challenge
    if challenge.iter().all(|&b| b == 0) {
        return false;
    }

    // Verify equation
    crypto::verify_equation_raw(
        &g_bytes, &h_bytes, &commitment, announcement,
        &challenge, response_s, response_r,
    )
}

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_commitment_hex() {
        assert!(!verify_proof("not-hex", "00".repeat(96).as_str(), "alice", "00".repeat(16).as_str()));
    }

    #[test]
    fn rejects_short_commitment() {
        let short = "00".repeat(31);
        assert!(!verify_proof(&short, &"00".repeat(96), "alice", &"00".repeat(16)));
    }

    #[test]
    fn rejects_identity_commitment() {
        let identity = "00".repeat(32);
        assert!(!verify_proof(&identity, &"42".repeat(96), "alice", &"00".repeat(16)));
    }

    #[test]
    fn rejects_random_proof() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        let random_proof = "42".repeat(96);
        // Random bytes won't satisfy the Sigma equation
        assert!(!verify_proof(&g, &random_proof, "alice", &"ab".repeat(16)));
    }

    #[test]
    fn rejects_short_proof() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        assert!(!verify_proof(&g, &"42".repeat(95), "alice", &"00".repeat(16)));
    }

    // --- Hardening tests (sprint-20) ---

    #[test]
    fn rejects_invalid_hex_in_commitment() {
        // "zz" is not valid hex
        assert!(!verify_proof("zzzzzz", &"00".repeat(96), "alice", &"00".repeat(16)));
    }

    #[test]
    fn rejects_invalid_hex_in_proof() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        assert!(!verify_proof(&g, "not_valid_hex_at_all", "alice", &"00".repeat(16)));
    }

    #[test]
    fn rejects_proof_hex_with_odd_length() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        // 191 hex chars = odd length, cannot decode to bytes
        let odd_hex = "a".repeat(191);
        assert!(!verify_proof(&g, &odd_hex, "alice", &"00".repeat(16)));
    }

    #[test]
    fn rejects_empty_client_id() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        let proof = "42".repeat(96);
        // Empty client_id should still be handled without panic and return false
        // (the proof is random garbage, so verification will fail)
        assert!(!verify_proof(&g, &proof, "", &"00".repeat(16)));
    }

    #[test]
    fn very_long_client_id_does_not_crash() {
        let g = hex::encode(crypto::generator_g().compress().to_bytes());
        let proof = "42".repeat(96);
        // 10KB client_id — must not panic or crash
        let long_id = "x".repeat(10 * 1024);
        // The proof is random, so it won't verify, but no crash
        assert!(!verify_proof(&g, &proof, &long_id, &"00".repeat(16)));
    }
}
