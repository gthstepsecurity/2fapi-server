// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! pg_2fapi — Zero-Knowledge Proof authentication for PostgreSQL
//!
//! Architecture:
//! - `domain/` — Pure business logic (testable with `cargo test`, no pgrx dependency)
//! - `infrastructure/` — PostgreSQL integration (pgrx, SPI, GUC) — requires a pg feature
//!
//! Build domain tests (no pgrx needed):
//!   cargo test --no-default-features
//!
//! Build as PG extension (requires cargo-pgrx):
//!   cargo pgrx test pg17
//!
//! Supported PostgreSQL versions: 14, 15, 16, 17

pub mod domain;

// Infrastructure layer — only compiled when targeting a specific PG version.
#[cfg(any(feature = "pg14", feature = "pg15", feature = "pg16", feature = "pg17"))]
pub mod infrastructure;

// pgrx module magic — only when building as extension
#[cfg(any(feature = "pg14", feature = "pg15", feature = "pg16", feature = "pg17"))]
pgrx::pg_module_magic!();

/// Extension version (callable from SQL).
#[cfg(any(feature = "pg14", feature = "pg15", feature = "pg16", feature = "pg17"))]
#[pgrx::prelude::pg_extern(schema = "twofapi", immutable)]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
