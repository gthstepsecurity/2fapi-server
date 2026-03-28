// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Audit logging for security-relevant operations.
//!
//! FIX M5: All authentication-related operations are logged to twofapi.audit_log.

use pgrx::prelude::*;

/// Logs a security event to the audit table.
///
/// Silently ignores errors (audit logging must never break the main operation).
pub fn log_event(operation: &str, client_id: &str, success: bool, detail: &str) {
    let _ = Spi::run_with_args(
        "INSERT INTO twofapi.audit_log (operation, client_id, success, detail, client_addr, backend_pid) \
         VALUES ($1, $2, $3, $4, pg_catalog.inet_client_addr()::text, pg_catalog.pg_backend_pid())",
        Some(vec![
            (PgBuiltInOids::TEXTOID.oid(), operation.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), client_id.into_datum()),
            (PgBuiltInOids::BOOLOID.oid(), success.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), detail.into_datum()),
        ]),
    );
}

/// Checks if the CALLING user (not the DEFINER) has the twofapi_admin role.
///
/// FIX C3: Administrative functions require this role.
/// FIX C-009: Uses session_user (original caller), NOT current_user
/// (which returns the DEFINER in SECURITY DEFINER functions).
pub fn require_admin() -> bool {
    let result = Spi::get_one::<bool>(
        "SELECT pg_catalog.pg_has_role(session_user, 'twofapi_admin', 'MEMBER')",
    );
    matches!(result, Ok(Some(true)))
}

/// Returns the current transaction ID (for session binding).
pub fn current_txid() -> i64 {
    Spi::get_one::<i64>("SELECT pg_catalog.txid_current()::bigint")
        .unwrap_or(Some(0))
        .unwrap_or(0)
}
