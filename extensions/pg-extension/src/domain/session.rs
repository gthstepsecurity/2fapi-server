// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Session management domain logic.
//!
//! Tracks authenticated sessions. In PostgreSQL, sessions map to
//! GUC (Grand Unified Configuration) variables set per-transaction.

/// A verified authentication session.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatedSession {
    pub client_id: String,
    pub verified_at_ms: u64,
}

/// Checks if a session is still valid (within the session TTL).
///
/// FIX L1: Uses checked_sub to prevent u64 underflow on clock drift.
/// If the clock went backward (now < verified_at), the session is treated as expired.
pub fn is_session_valid(session: &AuthenticatedSession, now_ms: u64, session_ttl_ms: u64) -> bool {
    match now_ms.checked_sub(session.verified_at_ms) {
        Some(elapsed) => elapsed < session_ttl_ms,
        None => false,
    }
}

/// Default session TTL: 15 minutes (matches token TTL).
pub const DEFAULT_SESSION_TTL_MS: u64 = 15 * 60 * 1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_valid_within_ttl() {
        let session = AuthenticatedSession {
            client_id: "alice".into(),
            verified_at_ms: 1000,
        };
        assert!(is_session_valid(&session, 1000 + 60_000, DEFAULT_SESSION_TTL_MS));
    }

    #[test]
    fn session_expired_at_exact_ttl() {
        let session = AuthenticatedSession {
            client_id: "alice".into(),
            verified_at_ms: 1000,
        };
        assert!(!is_session_valid(&session, 1000 + DEFAULT_SESSION_TTL_MS, DEFAULT_SESSION_TTL_MS));
    }

    #[test]
    fn session_expired_after_ttl() {
        let session = AuthenticatedSession {
            client_id: "alice".into(),
            verified_at_ms: 1000,
        };
        assert!(!is_session_valid(&session, 1000 + DEFAULT_SESSION_TTL_MS + 1, DEFAULT_SESSION_TTL_MS));
    }
}
