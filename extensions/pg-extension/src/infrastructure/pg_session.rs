// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL adapter for session management.
//!
//! FIX C1: Session state in Rust process memory (thread_local), not GUC.
//! FIX B-005: current_client() verifies challenge was consumed (not rolled back).

use pgrx::prelude::*;

use super::session_state;
use super::pg_audit;

/// Authenticates a client: verifies proof and establishes a session.
///
/// FIX B-005: Records challenge_id in session for SAVEPOINT replay detection.
///
/// Usage: SELECT twofapi.authenticate('my-service', 'ch-abc123', proof_bytes);
#[pg_extern(schema = "twofapi")]
fn authenticate(client_id: &str, challenge_id: &str, proof: &[u8]) -> bool {
    // Delegate to verify logic (this consumes the challenge via SPI DELETE)
    let valid = super::pg_verify::verify_internal(client_id, challenge_id, proof, &[]);

    if !valid {
        pg_audit::log_event("authenticate", client_id, false, "proof verification failed");
        return false;
    }

    // Store session with challenge_id for SAVEPOINT replay detection
    let txid = pg_audit::current_txid();
    session_state::set_session(client_id, txid, challenge_id);

    pg_audit::log_event("authenticate", client_id, true, "session established");
    true
}

/// Returns the currently authenticated client ID, or NULL if not authenticated.
///
/// FIX B-005: Verifies the challenge was actually consumed (not rolled back via
/// SAVEPOINT). If the challenge still exists in the DB, the session is invalid.
///
/// Usage in RLS: CREATE POLICY zkp ON my_data USING (owner = twofapi.current_client());
#[pg_extern(schema = "twofapi")]
fn current_client() -> Option<String> {
    let txid = pg_audit::current_txid();
    let (client_id, challenge_id) = session_state::get_current_client(txid)?;

    // FIX B-005: Verify the challenge was actually consumed (not rolled back).
    // If ROLLBACK TO restored the challenge, it still exists → session invalid.
    let challenge_exists = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS(SELECT 1 FROM twofapi.challenges WHERE challenge_id = $1)",
        vec![(PgBuiltInOids::TEXTOID.oid(), challenge_id.as_str().into_datum())],
    );

    match challenge_exists {
        Ok(Some(true)) => {
            // Challenge was rolled back → session is fraudulent
            session_state::clear_session();
            None
        }
        Ok(Some(false)) | Ok(None) => {
            // Challenge consumed (deleted) → session is valid
            Some(client_id)
        }
        Err(_) => {
            // FIX A-008: SPI error → fail-closed (not fail-open)
            session_state::clear_session();
            None
        }
    }
}
