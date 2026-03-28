// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Challenge issuance domain logic.
//!
//! Generates cryptographically secure nonces for authentication challenges.

use rand::RngCore;

/// A pending authentication challenge.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge_id: String,
    pub client_id: String,
    pub nonce: Vec<u8>,
    pub created_at_ms: u64,
    pub ttl_ms: u64,
}

/// Default challenge TTL: 2 minutes.
pub const DEFAULT_CHALLENGE_TTL_MS: u64 = 2 * 60 * 1000;

/// Generates a fresh challenge with a cryptographically random nonce.
///
/// FIX I-002: challenge_id uses INDEPENDENT random bytes (not derived from nonce).
/// This prevents nonce entropy leakage via the challenge_id.
pub fn generate_challenge(
    client_id: &str,
    now_ms: u64,
    ttl_ms: u64,
) -> Challenge {
    let mut nonce_bytes = [0u8; 16];
    let mut id_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);

    let nonce = nonce_bytes.to_vec();
    let challenge_id = format!("ch-{}", hex::encode(id_bytes));

    Challenge {
        challenge_id,
        client_id: client_id.to_string(),
        nonce,
        created_at_ms: now_ms,
        ttl_ms,
    }
}

/// Checks if a challenge has expired.
pub fn is_expired(challenge: &Challenge, now_ms: u64) -> bool {
    now_ms - challenge.created_at_ms >= challenge.ttl_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_challenges() {
        let c1 = generate_challenge("alice", 1000, DEFAULT_CHALLENGE_TTL_MS);
        let c2 = generate_challenge("alice", 1000, DEFAULT_CHALLENGE_TTL_MS);
        assert_ne!(c1.challenge_id, c2.challenge_id);
        assert_ne!(c1.nonce, c2.nonce);
    }

    #[test]
    fn challenge_has_correct_client_id() {
        let c = generate_challenge("alice-payments", 1000, DEFAULT_CHALLENGE_TTL_MS);
        assert_eq!(c.client_id, "alice-payments");
    }

    #[test]
    fn challenge_not_expired_within_ttl() {
        let c = generate_challenge("alice", 1000, 120_000);
        assert!(!is_expired(&c, 1000 + 90_000)); // 90s < 120s
    }

    #[test]
    fn challenge_expired_at_exact_ttl() {
        let c = generate_challenge("alice", 1000, 120_000);
        assert!(is_expired(&c, 1000 + 120_000)); // exactly at TTL = expired
    }

    #[test]
    fn challenge_expired_after_ttl() {
        let c = generate_challenge("alice", 1000, 120_000);
        assert!(is_expired(&c, 1000 + 180_000)); // 180s > 120s
    }

    #[test]
    fn nonce_is_16_bytes() {
        let c = generate_challenge("alice", 1000, DEFAULT_CHALLENGE_TTL_MS);
        assert_eq!(c.nonce.len(), 16);
    }
}
