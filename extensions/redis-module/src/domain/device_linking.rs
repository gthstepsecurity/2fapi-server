// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Device linking domain logic.
//!
//! Implements the BIP-39 chained hash protocol for pairing new devices.
//! The server only stores the salted hash — never the indexes or words.

use twofapi_crypto_core::bip39;

/// Result of a link verification attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkVerifyResult {
    /// Hash matches — pending confirmation from Device A.
    PendingConfirmation,
    /// Hash does not match.
    HashMismatch,
    /// Link request expired.
    Expired,
    /// Too many attempts.
    TooManyAttempts,
    /// Link request not found.
    NotFound,
}

/// Maximum verification attempts per link request.
pub const MAX_LINK_ATTEMPTS: i32 = 3;

/// Link request TTL in seconds.
pub const LINK_TTL_SECONDS: i64 = 60;

/// Salt length for anti-rainbow-table protection.
pub const LINK_SALT_LEN: usize = 16;

/// Generates a random salt for a link request.
pub fn generate_link_salt() -> [u8; LINK_SALT_LEN] {
    let mut salt = [0u8; LINK_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    salt
}

/// Generates a unique link ID.
pub fn generate_link_id() -> String {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    format!("lk-{}", hex::encode(bytes))
}

/// Verifies that a submitted hash matches the expected hash (constant-time).
pub fn verify_link_hash(expected: &[u8], submitted: &[u8]) -> bool {
    if expected.len() != 64 || submitted.len() != 64 {
        return false;
    }
    use subtle::ConstantTimeEq;
    bool::from(expected.ct_eq(submitted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_link_salt_is_correct_length() {
        let salt = generate_link_salt();
        assert_eq!(salt.len(), LINK_SALT_LEN);
    }

    #[test]
    fn generate_link_salt_is_random() {
        let s1 = generate_link_salt();
        let s2 = generate_link_salt();
        assert_ne!(s1, s2);
    }

    #[test]
    fn generate_link_id_has_prefix() {
        let id = generate_link_id();
        assert!(id.starts_with("lk-"));
        assert_eq!(id.len(), 3 + 16); // "lk-" + 16 hex chars
    }

    #[test]
    fn verify_link_hash_accepts_matching() {
        let hash = [0x42u8; 64];
        assert!(verify_link_hash(&hash, &hash));
    }

    #[test]
    fn verify_link_hash_rejects_different() {
        let h1 = [0x42u8; 64];
        let mut h2 = [0x42u8; 64];
        h2[0] = 0x43;
        assert!(!verify_link_hash(&h1, &h2));
    }

    #[test]
    fn verify_link_hash_rejects_wrong_length() {
        let h1 = [0x42u8; 64];
        let h2 = [0x42u8; 32];
        assert!(!verify_link_hash(&h1, &h2));
    }

    #[test]
    fn chained_hash_with_salt_works() {
        let salt = generate_link_salt();
        let h = bip39::chained_hash(&[100, 200, 300, 400], &salt).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn same_indexes_different_salt_different_hash() {
        let s1 = generate_link_salt();
        let s2 = generate_link_salt();
        let h1 = bip39::chained_hash(&[100, 200, 300, 400], &s1).unwrap();
        let h2 = bip39::chained_hash(&[100, 200, 300, 400], &s2).unwrap();
        assert_ne!(h1, h2);
    }
}
