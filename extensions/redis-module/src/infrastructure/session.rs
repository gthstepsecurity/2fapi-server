// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Per-connection session state stored in Rust process memory.
//!
//! Redis is single-threaded, so thread_local is equivalent to global state.
//! This is intentional — sessions are tracked by Redis client connection ID.
//!
//! Session state is NOT stored in Redis keys, preventing:
//! - Session spoofing via native SET commands (RD-045)
//! - Session data leakage via DUMP/MONITOR (RD-050/051)
//! - Session persistence in RDB/AOF snapshots (RD-073)

use std::cell::RefCell;
use std::collections::HashMap;

use crate::domain::acl::ConnectionAuth;

thread_local! {
    /// Maps Redis client connection ID → authenticated session.
    /// Only module command handlers can read/write this.
    static SESSIONS: RefCell<HashMap<u64, ConnectionAuth>> = RefCell::new(HashMap::new());

    /// Module-level statistics (not persisted).
    static STATS: RefCell<ModuleStats> = RefCell::new(ModuleStats::default());
}

#[derive(Default)]
pub struct ModuleStats {
    pub total_enrollments: u64,
    pub total_challenges: u64,
    pub total_verifications: u64,
    pub total_denied: u64,
    pub total_revocations: u64,
}

/// Maximum concurrent sessions (FIX E53: prevents OOM panic).
const MAX_SESSIONS: usize = 10_000;

/// Records a successful authentication for a connection.
///
/// FIX E53/A-001: Returns false if session could not be stored (capacity reached).
/// The caller MUST check the return value and report failure to the client.
pub fn set_session(client_conn_id: u64, auth: ConnectionAuth) -> bool {
    SESSIONS.with(|s| {
        let mut sessions = s.borrow_mut();
        // Allow overwriting existing session for the same connection
        if sessions.contains_key(&client_conn_id) {
            sessions.insert(client_conn_id, auth);
            return true;
        }
        // Check capacity
        if sessions.len() >= MAX_SESSIONS {
            return false;
        }
        sessions.insert(client_conn_id, auth);
        true
    })
}

/// Returns the authenticated session for a connection, if valid.
pub fn get_session(client_conn_id: u64, now_ms: u64) -> Option<ConnectionAuth> {
    SESSIONS.with(|s| {
        let sessions = s.borrow();
        sessions.get(&client_conn_id).and_then(|auth| {
            if auth.is_valid(now_ms) {
                Some(auth.clone())
            } else {
                None
            }
        })
    })
}

/// Removes a session (on disconnect or explicit logout).
pub fn clear_session(client_conn_id: u64) {
    SESSIONS.with(|s| {
        s.borrow_mut().remove(&client_conn_id);
    });
}

/// Removes all sessions for a given client_id (on revocation).
pub fn clear_sessions_for_client(client_id: &str) {
    SESSIONS.with(|s| {
        s.borrow_mut().retain(|_, auth| auth.client_id != client_id);
    });
}

/// Removes expired sessions (periodic cleanup).
pub fn cleanup_expired_sessions(now_ms: u64) -> usize {
    SESSIONS.with(|s| {
        let before = s.borrow().len();
        s.borrow_mut().retain(|_, auth| auth.is_valid(now_ms));
        before - s.borrow().len()
    })
}

pub fn update_stats(f: impl FnOnce(&mut ModuleStats)) {
    STATS.with(|s| f(&mut s.borrow_mut()));
}

pub fn get_stats() -> ModuleStats {
    STATS.with(|s| {
        let stats = s.borrow();
        ModuleStats {
            total_enrollments: stats.total_enrollments,
            total_challenges: stats.total_challenges,
            total_verifications: stats.total_verifications,
            total_denied: stats.total_denied,
            total_revocations: stats.total_revocations,
        }
    })
}

pub fn session_count() -> usize {
    SESSIONS.with(|s| s.borrow().len())
}
