// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Client enrollment and lifecycle management for Redis module.
//!
//! Pure domain logic — no Redis dependency.
//!
//! FIX C2/M3: Client ID validation prevents namespace injection.

use twofapi_crypto_core as crypto;

use super::acl::INTERNAL_KEY_PREFIX;

/// Client status in the Redis store.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientStatus {
    Active,
    Suspended,
    Revoked,
    Unknown,
}

impl ClientStatus {
    pub fn from_str(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "revoked" => Self::Revoked,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }

    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Validates a client_id for safe use in key patterns and namespaces.
///
/// FIX C2: Prevents namespace injection attacks where a client_id like "2fapi"
/// could grant access to internal module keys.
///
/// Rules:
/// - 1-128 characters
/// - Alphanumeric, hyphens, underscores, dots only
/// - Must not start with "2fapi", "_2fapi", or "twofapi" (reserved namespace)
/// - Must not contain ".." (path traversal prevention)
/// - Must not contain ":" (Redis key separator)
pub fn validate_client_id(client_id: &str) -> Result<(), String> {
    if client_id.is_empty() || client_id.len() > 128 {
        return Err(format!("client_id must be 1-128 characters, got {}", client_id.len()));
    }
    if !client_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err("client_id must contain only alphanumeric, hyphens, underscores, dots".into());
    }
    let lower = client_id.to_ascii_lowercase();
    if lower.starts_with("2fapi") || lower.starts_with("_2fapi") || lower.starts_with("twofapi") {
        return Err("client_id must not start with reserved prefix".into());
    }
    if client_id.contains("..") {
        return Err("client_id must not contain '..'".into());
    }
    Ok(())
}

/// Validates a commitment for enrollment (same rules as PG extension).
pub fn validate_enrollment(commitment: &[u8]) -> Result<(), String> {
    if commitment.len() != 32 {
        return Err(format!("Commitment must be 32 bytes, got {}", commitment.len()));
    }

    if !crypto::is_canonical_point_slice(commitment) {
        return Err("Not a canonical Ristretto255 point".into());
    }

    if crypto::is_identity_slice(commitment) {
        return Err("Commitment must not be the identity element".into());
    }

    Ok(())
}

/// Redis key patterns for the 2FAPI module.
///
/// FIX C2: Internal keys use the INTERNAL_KEY_PREFIX which cannot clash
/// with validated client_ids.
pub mod keys {
    use super::INTERNAL_KEY_PREFIX;

    /// The internal key prefix (re-exported for infrastructure layer).
    pub const INTERNAL_PREFIX: &str = INTERNAL_KEY_PREFIX;

    pub fn client_key(client_id: &str) -> String {
        format!("{}client:{}", INTERNAL_KEY_PREFIX, client_id)
    }

    pub fn challenge_key(challenge_id: &str) -> String {
        format!("{}challenge:{}", INTERNAL_KEY_PREFIX, challenge_id)
    }

    pub fn session_key(connection_id: u64) -> String {
        format!("{}session:{}", INTERNAL_KEY_PREFIX, connection_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_from_str() {
        assert_eq!(ClientStatus::from_str("active"), ClientStatus::Active);
        assert_eq!(ClientStatus::from_str("suspended"), ClientStatus::Suspended);
        assert_eq!(ClientStatus::from_str("revoked"), ClientStatus::Revoked);
        assert_eq!(ClientStatus::from_str("garbage"), ClientStatus::Unknown);
    }

    #[test]
    fn active_can_authenticate() {
        assert!(ClientStatus::Active.can_authenticate());
        assert!(!ClientStatus::Suspended.can_authenticate());
        assert!(!ClientStatus::Revoked.can_authenticate());
        assert!(!ClientStatus::Unknown.can_authenticate());
    }

    #[test]
    fn rejects_short_commitment() {
        assert!(validate_enrollment(&[0u8; 31]).is_err());
    }

    #[test]
    fn rejects_identity_commitment() {
        assert!(validate_enrollment(&[0u8; 32]).is_err());
    }

    #[test]
    fn accepts_valid_commitment() {
        let g = crypto::generator_g().compress().to_bytes();
        assert!(validate_enrollment(&g).is_ok());
    }

    #[test]
    fn key_patterns_use_internal_prefix() {
        assert!(keys::client_key("alice").starts_with(INTERNAL_KEY_PREFIX));
        assert!(keys::challenge_key("ch-123").starts_with(INTERNAL_KEY_PREFIX));
        assert!(keys::session_key(42).starts_with(INTERNAL_KEY_PREFIX));
    }

    // --- Red team audit fixes ---

    #[test]
    fn rejects_empty_client_id() {
        assert!(validate_client_id("").is_err());
    }

    #[test]
    fn rejects_too_long_client_id() {
        let long = "a".repeat(129);
        assert!(validate_client_id(&long).is_err());
    }

    #[test]
    fn rejects_reserved_prefix_2fapi() {
        assert!(validate_client_id("2fapi").is_err());
        assert!(validate_client_id("2fapi-service").is_err());
        assert!(validate_client_id("2FAPI").is_err());
    }

    #[test]
    fn rejects_reserved_prefix_twofapi() {
        assert!(validate_client_id("twofapi").is_err());
        assert!(validate_client_id("twofapi_internal").is_err());
    }

    #[test]
    fn rejects_reserved_prefix_underscore_2fapi() {
        assert!(validate_client_id("_2fapi_sys").is_err());
    }

    #[test]
    fn rejects_special_characters() {
        assert!(validate_client_id("alice:bob").is_err());  // colon
        assert!(validate_client_id("alice/bob").is_err());  // slash
        assert!(validate_client_id("alice bob").is_err());  // space
        assert!(validate_client_id("alice\nbob").is_err()); // newline
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_client_id("alice..bob").is_err());
    }

    #[test]
    fn accepts_valid_client_ids() {
        assert!(validate_client_id("alice").is_ok());
        assert!(validate_client_id("payment-service").is_ok());
        assert!(validate_client_id("my_app.v2").is_ok());
        assert!(validate_client_id("Service-123").is_ok());
    }
}
