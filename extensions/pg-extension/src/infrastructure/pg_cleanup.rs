// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL adapter for maintenance operations.
//!
//! FIX C3: Administrative functions require the twofapi_admin role.

use pgrx::prelude::*;

use super::pg_audit;

/// Removes expired challenges AND old audit log entries. Returns the number
/// of deleted challenge rows.
///
/// Also purges audit log entries older than `audit_retention_days` (default 30).
/// FIX A-004: Prevents unbounded audit log growth.
///
/// Requires twofapi_admin role.
///
/// Usage: SELECT twofapi.cleanup(30);  -- keep 30 days of audit log
///        SELECT twofapi.cleanup();     -- default: 30 days
#[pg_extern(schema = "twofapi")]
fn cleanup(audit_retention_days: default!(i32, 30)) -> i64 {
    if !pg_audit::require_admin() {
        pgrx::warning!("twofapi: cleanup requires twofapi_admin role");
        return -1;
    }

    // Clamp retention to sane range: 1-365 days
    let retention = audit_retention_days.max(1).min(365);

    // 1. Delete expired challenges
    let challenges_deleted = Spi::get_one::<i64>(
        "WITH deleted AS (DELETE FROM twofapi.challenges WHERE expires_at <= pg_catalog.now() RETURNING 1) \
         SELECT count(*) FROM deleted",
    ).unwrap_or(Some(0)).unwrap_or(0);

    // 2. Delete old audit log entries (FIX A-004)
    let retention_str = retention.to_string();
    let audit_deleted = Spi::get_one_with_args::<i64>(
        "WITH deleted AS ( \
             DELETE FROM twofapi.audit_log \
             WHERE ts < pg_catalog.now() - pg_catalog.make_interval(days => $1) \
             RETURNING 1 \
         ) SELECT count(*) FROM deleted",
        vec![(PgBuiltInOids::INT4OID.oid(), retention.into_datum())],
    ).unwrap_or(Some(0)).unwrap_or(0);

    pg_audit::log_event(
        "cleanup",
        "",
        true,
        &format!("challenges={} audit_log={} retention={}d", challenges_deleted, audit_deleted, retention),
    );

    challenges_deleted
}

/// Backward-compatible alias for cleanup with default retention.
///
/// Requires twofapi_admin role.
///
/// Usage: SELECT twofapi.cleanup_expired_challenges();
#[pg_extern(schema = "twofapi")]
fn cleanup_expired_challenges() -> i64 {
    cleanup(30)
}

/// Suspends a client (prevents new challenges and authentications).
///
/// Requires twofapi_admin role. FIX C3.
///
/// Usage: SELECT twofapi.suspend_client('my-service');
#[pg_extern(schema = "twofapi")]
fn suspend_client(client_id: &str) -> bool {
    if !pg_audit::require_admin() {
        pgrx::warning!("twofapi: suspend_client requires twofapi_admin role");
        pg_audit::log_event("suspend_client", client_id, false, "permission denied");
        return false;
    }

    let result = Spi::get_one_with_args::<i64>(
        "WITH updated AS ( \
             UPDATE twofapi.clients SET status = 'suspended', updated_at = pg_catalog.now() \
             WHERE client_id = $1 AND status = 'active' \
             RETURNING 1 \
         ) SELECT count(*) FROM updated",
        vec![(PgBuiltInOids::TEXTOID.oid(), client_id.into_datum())],
    );

    let success = matches!(result, Ok(Some(1)));
    pg_audit::log_event("suspend_client", client_id, success, "");
    success
}

/// Revokes a client permanently (cannot be re-activated).
///
/// Requires twofapi_admin role. FIX C3.
///
/// Usage: SELECT twofapi.revoke_client('my-service');
#[pg_extern(schema = "twofapi")]
fn revoke_client(client_id: &str) -> bool {
    if !pg_audit::require_admin() {
        pgrx::warning!("twofapi: revoke_client requires twofapi_admin role");
        pg_audit::log_event("revoke_client", client_id, false, "permission denied");
        return false;
    }

    let result = Spi::get_one_with_args::<i64>(
        "WITH updated AS ( \
             UPDATE twofapi.clients SET status = 'revoked', updated_at = pg_catalog.now() \
             WHERE client_id = $1 AND status != 'revoked' \
             RETURNING 1 \
         ) SELECT count(*) FROM updated",
        vec![(PgBuiltInOids::TEXTOID.oid(), client_id.into_datum())],
    );

    let success = matches!(result, Ok(Some(1)));
    pg_audit::log_event("revoke_client", client_id, success, "");
    success
}
