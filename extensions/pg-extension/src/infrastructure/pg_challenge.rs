// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL adapter for challenge issuance.
//!
//! FIX H1: Per-client concurrent challenge limit (max 10).
//! FIX H3: get_challenge_nonce requires client_id parameter.
//! FIX M2: No format! in SQL construction.
//! FIX L2: No unwrap() on SystemTime.

use pgrx::prelude::*;

use crate::domain::challenge;
use super::pg_audit;

/// Maximum concurrent challenges per client.
const MAX_CHALLENGES_PER_CLIENT: i64 = 10;

/// Default challenge TTL in seconds.
const CHALLENGE_TTL_SECONDS: i64 = (challenge::DEFAULT_CHALLENGE_TTL_MS / 1000) as i64;

/// Issues a new authentication challenge for a client.
///
/// Returns the challenge_id as TEXT, or NULL if:
/// - Client does not exist or is not active
/// - Client has too many pending challenges (FIX H1)
///
/// Usage: SELECT twofapi.issue_challenge('my-service');
#[pg_extern(schema = "twofapi")]
fn issue_challenge(client_id: &str) -> Option<String> {
    // 1. Check client exists and is active
    let client_exists = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS(SELECT 1 FROM twofapi.clients WHERE client_id = $1 AND status = 'active')",
        vec![(PgBuiltInOids::TEXTOID.oid(), client_id.into_datum())],
    );

    match client_exists {
        Ok(Some(true)) => {}
        _ => {
            pg_audit::log_event("issue_challenge", client_id, false, "client not found or inactive");
            return None;
        }
    }

    // FIX H1: Check concurrent challenge count
    let pending_count = Spi::get_one_with_args::<i64>(
        "SELECT count(*) FROM twofapi.challenges WHERE client_id = $1 AND expires_at > pg_catalog.now()",
        vec![(PgBuiltInOids::TEXTOID.oid(), client_id.into_datum())],
    );

    if let Ok(Some(count)) = pending_count {
        if count >= MAX_CHALLENGES_PER_CLIENT {
            pg_audit::log_event("issue_challenge", client_id, false, "too many pending challenges");
            return None;
        }
    }

    // 2. Generate challenge via domain logic
    // FIX L2: Handle SystemTime error gracefully
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let ch = challenge::generate_challenge(client_id, now_ms, challenge::DEFAULT_CHALLENGE_TTL_MS);

    // 3. Store challenge with SQL-computed expiration
    // FIX M2: Use make_interval instead of format! interpolation
    let result = Spi::run_with_args(
        "INSERT INTO twofapi.challenges (challenge_id, client_id, nonce, expires_at) \
         VALUES ($1, $2, $3, pg_catalog.now() + pg_catalog.make_interval(secs => $4::double precision))",
        Some(vec![
            (PgBuiltInOids::TEXTOID.oid(), ch.challenge_id.clone().into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), client_id.into_datum()),
            (PgBuiltInOids::BYTEAOID.oid(), ch.nonce.into_datum()),
            (PgBuiltInOids::INT8OID.oid(), CHALLENGE_TTL_SECONDS.into_datum()),
        ]),
    );

    match result {
        Ok(_) => {
            pg_audit::log_event("issue_challenge", client_id, true, &ch.challenge_id);
            Some(ch.challenge_id)
        }
        Err(_) => None,
    }
}

/// Returns the nonce for a given challenge (for client-side proof construction).
///
/// FIX H3: Requires client_id parameter — verifies challenge ownership.
///
/// Usage: SELECT twofapi.get_challenge_nonce('my-service', 'ch-abc123');
#[pg_extern(schema = "twofapi")]
fn get_challenge_nonce(client_id: &str, challenge_id: &str) -> Option<Vec<u8>> {
    let nonce = Spi::get_one_with_args::<Vec<u8>>(
        "SELECT nonce FROM twofapi.challenges \
         WHERE challenge_id = $1 AND client_id = $2 AND expires_at > pg_catalog.now()",
        vec![
            (PgBuiltInOids::TEXTOID.oid(), challenge_id.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), client_id.into_datum()),
        ],
    );

    match nonce {
        Ok(Some(n)) => Some(n),
        _ => None,
    }
}
