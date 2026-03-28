// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Key-level access control for Redis module.
//!
//! After authentication, a connection is marked as "verified" for a specific client.
//! Subsequent commands can check this before granting access to keys.
//!
//! FIX C2: Internal keys use `_2fapi_sys/` prefix, which cannot clash with
//! validated client_ids (client_ids cannot start with "_2fapi").
//! FIX L1: Uses saturating_sub to prevent u64 underflow.

/// Per-connection authentication state.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionAuth {
    pub client_id: String,
    pub verified_at_ms: u64,
    pub session_ttl_ms: u64,
}

/// Default session TTL: 15 minutes.
pub const DEFAULT_SESSION_TTL_MS: u64 = 15 * 60 * 1000;

impl ConnectionAuth {
    pub fn new(client_id: String, verified_at_ms: u64) -> Self {
        Self {
            client_id,
            verified_at_ms,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
        }
    }

    /// Checks if the session is still valid.
    ///
    /// FIX L1: Uses checked_sub to prevent underflow on clock drift.
    /// If the clock went backward (now < verified_at), the session is treated as expired.
    pub fn is_valid(&self, now_ms: u64) -> bool {
        match now_ms.checked_sub(self.verified_at_ms) {
            Some(elapsed) => elapsed < self.session_ttl_ms,
            None => false, // Clock drift backward — treat as expired for safety
        }
    }

    /// Checks if the authenticated client can access a key.
    ///
    /// A key is accessible if:
    /// 1. The session is valid (not expired)
    /// 2. The key belongs to the authenticated client (prefix match)
    /// 3. The key is NOT in the internal namespace (FIX C2)
    pub fn can_access_key(&self, key: &str, now_ms: u64) -> bool {
        if !self.is_valid(now_ms) {
            return false;
        }

        // FIX C2: Block access to internal module keys regardless of client_id
        if key.starts_with(INTERNAL_KEY_PREFIX) {
            return false;
        }

        // Key must start with the client's namespace
        let prefix = format!("{}:", self.client_id);
        key.starts_with(&prefix) || key == self.client_id
    }
}

/// Internal key prefix for module state. Client IDs cannot start with "_2fapi"
/// (validated at enrollment), so this namespace is always isolated.
pub const INTERNAL_KEY_PREFIX: &str = "_2fapi_sys/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_valid_within_ttl() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(auth.is_valid(1000 + 60_000)); // 1 min < 15 min
    }

    #[test]
    fn session_expired_at_ttl() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(!auth.is_valid(1000 + DEFAULT_SESSION_TTL_MS));
    }

    #[test]
    fn can_access_own_keys() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(auth.can_access_key("alice:data", 2000));
        assert!(auth.can_access_key("alice:session:123", 2000));
    }

    #[test]
    fn cannot_access_other_client_keys() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(!auth.can_access_key("bob:data", 2000));
        assert!(!auth.can_access_key("eve:secret", 2000));
    }

    #[test]
    fn cannot_access_when_expired() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(!auth.can_access_key("alice:data", 1000 + DEFAULT_SESSION_TTL_MS));
    }

    #[test]
    fn can_access_exact_client_id_key() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(auth.can_access_key("alice", 2000));
    }

    // --- Hardening tests (sprint-20) ---

    #[test]
    fn path_traversal_in_key_is_denied() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(
            !auth.can_access_key("alice/../bob:data", 2000),
            "Path traversal attempt must be denied"
        );
    }

    #[test]
    fn empty_key_is_denied() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(
            !auth.can_access_key("", 2000),
            "Empty key must be denied"
        );
    }

    #[test]
    fn key_exactly_matching_client_id_is_allowed() {
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(
            auth.can_access_key("alice", 2000),
            "Key exactly matching client_id must be allowed"
        );
    }

    // --- Red team audit fixes ---

    #[test]
    fn internal_keys_are_always_blocked() {
        // FIX C2: Even if client_id somehow matches, internal keys are blocked
        let auth = ConnectionAuth::new("_2fapi_sys".into(), 1000);
        assert!(
            !auth.can_access_key("_2fapi_sys/client:alice", 2000),
            "Internal keys must always be blocked"
        );
    }

    #[test]
    fn namespace_injection_via_2fapi_client_id_blocked() {
        // FIX C2: A client named "2fapi" should not access internal keys
        // (Note: "2fapi" is now rejected at enrollment, but defense-in-depth)
        let auth = ConnectionAuth::new("2fapi".into(), 1000);
        assert!(
            !auth.can_access_key("_2fapi_sys/client:alice", 2000),
            "Client '2fapi' must not access internal namespace"
        );
    }

    #[test]
    fn clock_drift_backward_does_not_panic() {
        // FIX L1: Clock goes backward — should not panic, just report expired
        let auth = ConnectionAuth::new("alice".into(), 1000);
        assert!(!auth.is_valid(500)); // now < verified_at → expired, no panic
    }
}
