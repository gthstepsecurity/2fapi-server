// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL adapter for proof verification.
//!
//! FIX M5: Audit logging on verification attempts.

use pgrx::prelude::*;

use crate::domain::verification::{self, VerificationResult};
use super::pg_audit;

/// Verifies a ZKP proof against a stored commitment and challenge.
///
/// Returns `true` if the proof is valid. Returns `false` on any failure
/// (invalid proof, expired challenge, unknown client) — indistinguishable
/// for security.
///
/// The challenge is consumed (deleted) on verification attempt to prevent replay.
///
/// Usage: SELECT twofapi.verify('my-service', 'ch-abc123', proof_bytes);
#[pg_extern(schema = "twofapi")]
pub fn verify(client_id: &str, challenge_id: &str, proof: &[u8]) -> bool {
    let result = verify_internal(client_id, challenge_id, proof, &[]);
    pg_audit::log_event("verify", client_id, result, "");
    result
}

/// Verifies a ZKP proof with optional channel binding data.
///
/// Usage: SELECT twofapi.verify_with_binding('my-service', 'ch-abc123', proof_bytes, binding_bytes);
#[pg_extern(schema = "twofapi")]
pub fn verify_with_binding(client_id: &str, challenge_id: &str, proof: &[u8], channel_binding: &[u8]) -> bool {
    let result = verify_internal(client_id, challenge_id, proof, channel_binding);
    pg_audit::log_event("verify_with_binding", client_id, result, "");
    result
}

/// Maximum channel binding size (1 KB). Prevents allocation attacks (PG-051).
const MAX_CHANNEL_BINDING_LEN: usize = 1024;

/// Internal verification logic shared by verify and authenticate.
pub fn verify_internal(client_id: &str, challenge_id: &str, proof: &[u8], channel_binding: &[u8]) -> bool {
    // FIX PG-051: Reject oversized channel binding to prevent allocation attacks
    if channel_binding.len() > MAX_CHANNEL_BINDING_LEN {
        return false;
    }
    // 1. Fetch client commitment
    let commitment = Spi::get_one_with_args::<Vec<u8>>(
        "SELECT commitment FROM twofapi.clients WHERE client_id = $1 AND status = 'active'",
        vec![(PgBuiltInOids::TEXTOID.oid(), client_id.into_datum())],
    );

    let commitment = match commitment {
        Ok(Some(c)) => c,
        _ => return false,
    };

    // 2. Fetch and consume challenge (delete to prevent replay)
    let nonce = Spi::get_one_with_args::<Vec<u8>>(
        "DELETE FROM twofapi.challenges \
         WHERE challenge_id = $1 AND client_id = $2 AND expires_at > pg_catalog.now() \
         RETURNING nonce",
        vec![
            (PgBuiltInOids::TEXTOID.oid(), challenge_id.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), client_id.into_datum()),
        ],
    );

    let nonce = match nonce {
        Ok(Some(n)) => n,
        _ => return false,
    };

    // 3. Verify proof via domain logic
    let result = verification::verify_proof(
        &commitment,
        proof,
        client_id,
        &nonce,
        channel_binding,
    );

    matches!(result, VerificationResult::Valid)
}
