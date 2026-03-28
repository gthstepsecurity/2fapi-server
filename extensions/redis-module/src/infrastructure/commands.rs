// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Redis command handlers for 2FApi authentication.
//!
//! Each command handler is atomic by virtue of Redis's single-threaded model.
//!
//! Security fixes applied:
//! - RD-023/033: Atomic challenge consumption
//! - RD-055/C31: Explicit EXISTS handling (no wildcard catch-all)
//! - A1: Connection ID failure → error (no fallback to 0)
//! - B13/E53: Session cleanup + max cap
//! - D49/D50: Client ID validation on ALL commands

use redis_module::{Context, RedisError, RedisResult, RedisString, RedisValue};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{acl, challenge_store, client_store, verification};
use super::session;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Maximum challenge_id length (prevents oversized key names).
const MAX_CHALLENGE_ID_LEN: usize = 128;

/// FIX A1: Returns connection ID or error. Never falls back to 0.
fn get_conn_id(ctx: &Context) -> Result<u64, RedisError> {
    match ctx.call("CLIENT", &["ID"]) {
        Ok(RedisValue::Integer(id)) if id > 0 => Ok(id as u64),
        Ok(RedisValue::Integer(_)) => Err(RedisError::Str("ERR invalid connection ID")),
        _ => Err(RedisError::Str("ERR cannot determine connection ID")),
    }
}

/// FIX D49: Validates client_id on every command (not just ENROLL).
fn validate_input_client_id(client_id: &str) -> Result<(), RedisError> {
    if let Err(e) = client_store::validate_client_id(client_id) {
        return Err(RedisError::String(e));
    }
    Ok(())
}

/// FIX D50: Validates challenge_id length.
fn validate_challenge_id(challenge_id: &str) -> Result<(), RedisError> {
    if challenge_id.is_empty() || challenge_id.len() > MAX_CHALLENGE_ID_LEN {
        return Err(RedisError::Str("ERR invalid challenge_id length"));
    }
    Ok(())
}

// ============================================================
// 2FAPI.ENROLL <client_id> <commitment_hex>
// ============================================================

pub fn cmd_enroll(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    // FIX B13: Periodic session cleanup on high-traffic paths
    session::cleanup_expired_sessions(now_ms());

    let client_id = args[1].to_string_lossy();
    let commitment_hex = args[2].to_string_lossy();

    validate_input_client_id(&client_id)?;

    if commitment_hex.len() != 64 {
        return Err(RedisError::Str(
            "ERR commitment must be exactly 64 hex chars (32 bytes)",
        ));
    }

    let commitment = match hex::decode(&*commitment_hex) {
        Ok(c) => c,
        Err(_) => return Err(RedisError::Str("ERR invalid hex encoding")),
    };

    if let Err(e) = client_store::validate_enrollment(&commitment) {
        return Err(RedisError::String(e));
    }

    let key = client_store::keys::client_key(&client_id);

    // FIX C31: Explicit match — errors are NOT treated as "not exists"
    match ctx.call("EXISTS", &[key.as_str()]) {
        Ok(RedisValue::Integer(0)) => {} // Key does not exist — proceed
        Ok(RedisValue::Integer(_)) => {
            return Err(RedisError::Str("ERR client already enrolled"));
        }
        Ok(_) => {
            return Err(RedisError::Str("ERR unexpected EXISTS response"));
        }
        Err(e) => return Err(e),
    }

    let ts = now_ms().to_string();
    ctx.call(
        "HSET",
        &[
            key.as_str(),
            "commitment",
            &*commitment_hex,
            "status",
            "active",
            "created_at",
            ts.as_str(),
        ],
    )?;

    session::update_stats(|s| s.total_enrollments += 1);

    Ok(RedisValue::SimpleStringStatic("OK"))
}

// ============================================================
// 2FAPI.CHALLENGE <client_id>
// ============================================================

pub fn cmd_challenge(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let client_id = args[1].to_string_lossy();

    // FIX D49: Validate client_id
    validate_input_client_id(&client_id)?;

    let client_key = client_store::keys::client_key(&client_id);
    let status = call_hget(ctx, &client_key, "status")?;

    match status.as_deref() {
        Some("active") => {}
        _ => return Err(RedisError::Str("ERR client not found or inactive")),
    }

    let (challenge_id, nonce_hex) = challenge_store::generate_challenge(&client_id);
    let challenge_key = client_store::keys::challenge_key(&challenge_id);
    let ttl = challenge_store::DEFAULT_CHALLENGE_TTL_SECONDS.to_string();

    ctx.call(
        "HSET",
        &[
            challenge_key.as_str(),
            "client_id",
            &*client_id,
            "nonce",
            nonce_hex.as_str(),
        ],
    )?;

    // FIX A-002: If EXPIRE fails, delete the challenge to avoid immortal orphans
    if let Err(e) = ctx.call("EXPIRE", &[challenge_key.as_str(), ttl.as_str()]) {
        let _ = ctx.call("DEL", &[challenge_key.as_str()]);
        return Err(e);
    }

    session::update_stats(|s| s.total_challenges += 1);

    Ok(RedisValue::Array(vec![
        RedisValue::BulkString(challenge_id),
        RedisValue::BulkString(nonce_hex),
    ]))
}

// ============================================================
// 2FAPI.VERIFY <client_id> <challenge_id> <proof_hex>
// ============================================================

pub fn cmd_verify(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 4 {
        return Err(RedisError::WrongArity);
    }

    // FIX B13: Periodic session cleanup
    session::cleanup_expired_sessions(now_ms());

    let client_id = args[1].to_string_lossy();
    let challenge_id = args[2].to_string_lossy();
    let proof_hex = args[3].to_string_lossy();

    // FIX D49/D50: Validate inputs
    validate_input_client_id(&client_id)?;
    validate_challenge_id(&challenge_id)?;

    let challenge_key = client_store::keys::challenge_key(&challenge_id);

    // 1. Read challenge data
    let ch_client_id = call_hget(ctx, &challenge_key, "client_id")?;
    let ch_nonce = call_hget(ctx, &challenge_key, "nonce")?;

    // 2. Consume challenge IMMEDIATELY (atomic in single-threaded handler)
    ctx.call("DEL", &[challenge_key.as_str()])?;

    // 3. Validate challenge ownership
    let nonce_hex = match (ch_client_id, ch_nonce) {
        (Some(ref id), Some(nonce)) if id == &*client_id => nonce,
        _ => {
            session::update_stats(|s| s.total_denied += 1);
            return Ok(RedisValue::SimpleStringStatic("DENIED"));
        }
    };

    // 4. Read client commitment
    let client_key = client_store::keys::client_key(&client_id);
    let commitment_hex = call_hget(ctx, &client_key, "commitment")?;
    let status = call_hget(ctx, &client_key, "status")?;

    let commitment = match (commitment_hex, status) {
        (Some(c), Some(ref s)) if s == "active" => c,
        _ => {
            session::update_stats(|s| s.total_denied += 1);
            return Ok(RedisValue::SimpleStringStatic("DENIED"));
        }
    };

    // 5. Verify proof via domain logic
    let valid = verification::verify_proof(&commitment, &*proof_hex, &client_id, &nonce_hex);

    if !valid {
        session::update_stats(|s| s.total_denied += 1);
        return Ok(RedisValue::SimpleStringStatic("DENIED"));
    }

    // 6. Establish session (FIX A1: fail if conn_id unknown)
    let conn_id = get_conn_id(ctx)?;

    // FIX A-001: Check set_session return — fail if session table is full
    if !session::set_session(conn_id, acl::ConnectionAuth::new(client_id.to_string(), now_ms())) {
        return Err(RedisError::Str("ERR session capacity reached, try again later"));
    }

    session::update_stats(|s| s.total_verifications += 1);

    Ok(RedisValue::SimpleStringStatic("OK"))
}

// ============================================================
// 2FAPI.STATUS <client_id>
// ============================================================

pub fn cmd_status(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let client_id = args[1].to_string_lossy();
    // FIX D49: Validate client_id
    validate_input_client_id(&client_id)?;

    let client_key = client_store::keys::client_key(&client_id);
    let status = call_hget(ctx, &client_key, "status")?;

    match status {
        Some(s) => Ok(RedisValue::BulkString(s)),
        None => Ok(RedisValue::BulkString("unknown".to_string())),
    }
}

// ============================================================
// 2FAPI.REVOKE <client_id>
// ============================================================

pub fn cmd_revoke(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let client_id = args[1].to_string_lossy();
    validate_input_client_id(&client_id)?;

    let client_key = client_store::keys::client_key(&client_id);

    // FIX C31: Explicit EXISTS handling
    match ctx.call("EXISTS", &[client_key.as_str()]) {
        Ok(RedisValue::Integer(0)) => {
            return Err(RedisError::Str("ERR client not found"));
        }
        Ok(RedisValue::Integer(_)) => {} // exists
        Ok(_) => return Err(RedisError::Str("ERR unexpected response")),
        Err(e) => return Err(e),
    }

    ctx.call("HSET", &[client_key.as_str(), "status", "revoked"])?;
    session::clear_sessions_for_client(&client_id);
    session::update_stats(|s| s.total_revocations += 1);

    Ok(RedisValue::SimpleStringStatic("OK"))
}

// ============================================================
// 2FAPI.SUSPEND <client_id>   [FIX B27]
// ============================================================

/// Suspends a client and immediately invalidates sessions.
pub fn cmd_suspend(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let client_id = args[1].to_string_lossy();
    validate_input_client_id(&client_id)?;

    let client_key = client_store::keys::client_key(&client_id);

    let status = call_hget(ctx, &client_key, "status")?;
    match status.as_deref() {
        Some("active") => {}
        _ => return Err(RedisError::Str("ERR client not active")),
    }

    ctx.call("HSET", &[client_key.as_str(), "status", "suspended"])?;
    session::clear_sessions_for_client(&client_id);

    Ok(RedisValue::SimpleStringStatic("OK"))
}

// ============================================================
// 2FAPI.INFO
// ============================================================

pub fn cmd_info(_ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 1 {
        return Err(RedisError::WrongArity);
    }

    let stats = session::get_stats();
    let sessions = session::session_count();

    Ok(RedisValue::Array(vec![
        RedisValue::BulkString("version".to_string()),
        RedisValue::BulkString(env!("CARGO_PKG_VERSION").to_string()),
        RedisValue::BulkString("enrollments".to_string()),
        RedisValue::Integer(stats.total_enrollments as i64),
        RedisValue::BulkString("challenges".to_string()),
        RedisValue::Integer(stats.total_challenges as i64),
        RedisValue::BulkString("verifications".to_string()),
        RedisValue::Integer(stats.total_verifications as i64),
        RedisValue::BulkString("denied".to_string()),
        RedisValue::Integer(stats.total_denied as i64),
        RedisValue::BulkString("revocations".to_string()),
        RedisValue::Integer(stats.total_revocations as i64),
        RedisValue::BulkString("active_sessions".to_string()),
        RedisValue::Integer(sessions as i64),
    ]))
}

// ============================================================
// 2FAPI.WHOAMI
// ============================================================

pub fn cmd_whoami(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 1 {
        return Err(RedisError::WrongArity);
    }

    let conn_id = get_conn_id(ctx)?;
    let auth = session::get_session(conn_id, now_ms());

    match auth {
        Some(a) => Ok(RedisValue::BulkString(a.client_id)),
        None => Ok(RedisValue::Null),
    }
}

// ============================================================
// Helper
// ============================================================

fn call_hget(ctx: &Context, key: &str, field: &str) -> Result<Option<String>, RedisError> {
    match ctx.call("HGET", &[key, field]) {
        Ok(RedisValue::BulkString(s)) => Ok(Some(s)),
        Ok(RedisValue::SimpleString(s)) => Ok(Some(s)),
        Ok(RedisValue::Null) | Ok(RedisValue::NoReply) => Ok(None),
        Ok(_) => Ok(None),
        Err(e) => Err(e),
    }
}
