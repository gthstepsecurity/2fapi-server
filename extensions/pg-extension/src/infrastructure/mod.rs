// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! PostgreSQL infrastructure layer.
//!
//! Contains #[pg_extern] functions that expose the domain logic as SQL functions.
//! This module is only compiled when a pg feature (pg14-pg17) is enabled.
//!
//! Requires: cargo install cargo-pgrx && cargo pgrx init

pub mod session_state;
pub mod pg_audit;
pub mod pg_enroll;
pub mod pg_challenge;
pub mod pg_verify;
pub mod pg_session;
pub mod pg_cleanup;
