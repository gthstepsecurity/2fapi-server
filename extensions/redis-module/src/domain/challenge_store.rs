// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Challenge management for Redis module.
//!
//! Challenges in Redis are stored as hash keys with automatic TTL expiry.

use rand::RngCore;

/// Default challenge TTL: 2 minutes (120 seconds).
pub const DEFAULT_CHALLENGE_TTL_SECONDS: u64 = 120;

/// Generates a fresh challenge nonce.
///
/// FIX I-002: challenge_id uses INDEPENDENT random bytes (not derived from nonce).
/// This prevents nonce entropy leakage via the challenge_id.
///
/// Returns (challenge_id, nonce_hex).
pub fn generate_challenge(_client_id: &str) -> (String, String) {
    let mut nonce_bytes = [0u8; 16];
    let mut id_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);

    let nonce_hex = hex::encode(nonce_bytes);
    let challenge_id = format!("ch-{}", hex::encode(id_bytes));

    (challenge_id, nonce_hex)
}

/// Validates that a challenge belongs to the expected client.
pub fn validate_challenge_ownership(stored_client_id: &str, request_client_id: &str) -> bool {
    stored_client_id == request_client_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_challenges() {
        let (id1, nonce1) = generate_challenge("alice");
        let (id2, nonce2) = generate_challenge("alice");
        assert_ne!(id1, id2);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn challenge_id_has_prefix() {
        let (id, _) = generate_challenge("alice");
        assert!(id.starts_with("ch-"));
    }

    #[test]
    fn nonce_is_hex_encoded_16_bytes() {
        let (_, nonce) = generate_challenge("alice");
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validates_ownership_correctly() {
        assert!(validate_challenge_ownership("alice", "alice"));
        assert!(!validate_challenge_ownership("alice", "bob"));
    }
}
