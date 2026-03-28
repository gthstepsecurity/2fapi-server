// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Process-local session state — immune to GUC spoofing.
//!
//! FIX C1: Replaces GUC-based session tracking with Rust-side memory.
//! FIX B-005: Stores challenge_id to detect SAVEPOINT+ROLLBACK replay.
//!
//! Session is transaction-scoped: authenticate() records the txid,
//! and current_client() verifies it matches AND that the challenge
//! was actually consumed (not rolled back).

use std::cell::RefCell;

/// An authenticated session bound to a specific transaction.
#[derive(Clone, Debug)]
struct SessionState {
    /// The authenticated client identifier.
    client_id: String,
    /// The transaction ID when authentication occurred.
    txid: i64,
    /// The challenge_id consumed during authentication.
    /// Used to detect SAVEPOINT+ROLLBACK replay (FIX B-005).
    challenge_id: String,
}

thread_local! {
    /// Per-backend-process session state. Each PostgreSQL connection has its
    /// own backend process, so this is effectively per-connection.
    /// Only the extension's Rust code can access this — no SQL spoofing possible.
    static CURRENT_SESSION: RefCell<Option<SessionState>> = RefCell::new(None);
}

/// Records a successful authentication for the current transaction.
///
/// FIX B-005: Also records challenge_id for SAVEPOINT replay detection.
pub fn set_session(client_id: &str, txid: i64, challenge_id: &str) {
    CURRENT_SESSION.with(|s| {
        *s.borrow_mut() = Some(SessionState {
            client_id: client_id.to_string(),
            txid,
            challenge_id: challenge_id.to_string(),
        });
    });
}

/// Returns the authenticated client ID if the session is valid.
///
/// Returns None if:
/// - No authentication occurred
/// - The authentication was in a different transaction (txid mismatch)
///
/// Also returns the challenge_id so the caller can verify it was consumed.
/// FIX B-005: The caller MUST check that the challenge no longer exists in DB.
pub fn get_current_client(current_txid: i64) -> Option<(String, String)> {
    CURRENT_SESSION.with(|s| {
        let session = s.borrow();
        match session.as_ref() {
            Some(state) if state.txid == current_txid => {
                Some((state.client_id.clone(), state.challenge_id.clone()))
            }
            _ => None,
        }
    })
}

/// Clears the session state (used on transaction end or explicit logout).
pub fn clear_session() {
    CURRENT_SESSION.with(|s| {
        *s.borrow_mut() = None;
    });
}
