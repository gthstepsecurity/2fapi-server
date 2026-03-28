// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL adapter for client enrollment.
//!
//! FIX H2: Basic rate limiting via max clients check.
//! FIX M3/C2: Client ID validation (no reserved prefixes, safe characters).
//! FIX M5: Audit logging on enrollment.

use pgrx::prelude::*;

use crate::domain::enrollment;
use super::pg_audit;

/// Maximum number of enrolled clients (safety limit).
const MAX_CLIENTS: i64 = 100_000;

/// Validates a client_id for safe use in key patterns and namespaces.
///
/// Rules:
/// - 1-128 characters
/// - Alphanumeric, hyphens, underscores, dots only
/// - Must not start with "2fapi" or "_2fapi" (reserved namespace)
/// - Must not contain ".." (path traversal prevention)
fn validate_client_id(client_id: &str) -> Result<(), &'static str> {
    if client_id.is_empty() || client_id.len() > 128 {
        return Err("client_id must be 1-128 characters");
    }
    if !client_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err("client_id contains invalid characters");
    }
    let lower = client_id.to_ascii_lowercase();
    if lower.starts_with("2fapi") || lower.starts_with("_2fapi") || lower.starts_with("twofapi") {
        return Err("client_id must not use reserved prefix");
    }
    if client_id.contains("..") {
        return Err("client_id must not contain '..'");
    }
    Ok(())
}

/// Enrolls a new client with a Pedersen commitment and proof of possession.
///
/// Returns `true` on success. Returns `false` (not an error) if the client
/// already exists — this prevents client enumeration.
///
/// Usage: SELECT twofapi.enroll('my-service', commitment_bytes, proof_bytes);
#[pg_extern(schema = "twofapi")]
fn enroll(client_id: &str, commitment: &[u8], proof: &[u8]) -> bool {
    // FIX M3/C2: Validate client_id
    if let Err(reason) = validate_client_id(client_id) {
        pg_audit::log_event("enroll", client_id, false, reason);
        return false;
    }

    // FIX H2: Check total client count (basic rate limiting)
    let client_count = Spi::get_one::<i64>(
        "SELECT count(*) FROM twofapi.clients",
    );
    if let Ok(Some(count)) = client_count {
        if count >= MAX_CLIENTS {
            pg_audit::log_event("enroll", client_id, false, "max clients reached");
            return false;
        }
    }

    // 1. Validate commitment
    if let Err(_) = enrollment::validate_commitment(commitment) {
        pg_audit::log_event("enroll", client_id, false, "invalid commitment");
        return false;
    }

    // 2. Validate proof of possession
    if let Err(_) = enrollment::validate_proof_of_possession(proof) {
        pg_audit::log_event("enroll", client_id, false, "invalid proof encoding");
        return false;
    }

    // 3. Verify the proof actually opens the commitment
    let (g, h) = twofapi_crypto_core::generators();
    let g_bytes = g.compress().to_bytes();
    let h_bytes = h.compress().to_bytes();

    let transcript_bytes = crate::domain::transcript::build_transcript(
        crate::domain::transcript::PROTOCOL_TAG,
        &g_bytes,
        &h_bytes,
        commitment,
        &proof[0..32],  // announcement
        client_id.as_bytes(),
        &[],  // no nonce for enrollment
        b"enrollment",
    );
    let challenge = twofapi_crypto_core::hash_transcript_bytes(&transcript_bytes);

    if challenge.iter().all(|&b| b == 0) {
        pg_audit::log_event("enroll", client_id, false, "zero challenge");
        return false;
    }

    let valid = twofapi_crypto_core::verify_equation_raw(
        &g_bytes,
        &h_bytes,
        commitment,
        &proof[0..32],
        &challenge,
        &proof[32..64],
        &proof[64..96],
    );

    if !valid {
        pg_audit::log_event("enroll", client_id, false, "proof verification failed");
        return false;
    }

    // 4. Insert into database (idempotent — conflict returns false)
    let result = Spi::run_with_args(
        "INSERT INTO twofapi.clients (client_id, commitment) VALUES ($1, $2) \
         ON CONFLICT (client_id) DO NOTHING",
        Some(vec![
            (PgBuiltInOids::TEXTOID.oid(), client_id.into_datum()),
            (PgBuiltInOids::BYTEAOID.oid(), commitment.into_datum()),
        ]),
    );

    let success = result.is_ok();
    pg_audit::log_event("enroll", client_id, success, "");
    success
}
