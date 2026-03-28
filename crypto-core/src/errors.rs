// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Error types for the 2FApi cryptographic core.

use thiserror::Error;

/// Errors that may occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The provided bytes are not a canonical Ristretto255 point encoding.
    #[error("invalid point encoding: not a canonical Ristretto255 point")]
    InvalidPointEncoding,

    /// The provided bytes are not a canonical scalar (not reduced modulo l).
    #[error("invalid scalar encoding: not reduced modulo group order")]
    InvalidScalarEncoding,

    /// The point is the identity element, which is not allowed in this context.
    #[error("point is the identity element")]
    IdentityPoint,

    /// Input buffer has an unexpected length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Proof verification failed (equation did not hold).
    #[error("proof verification failed: equation z_s·G + z_r·H != A + c·C")]
    ProofVerificationFailed,

    /// Transcript hashing produced an invalid result.
    #[error("transcript hash failed")]
    TranscriptHashFailed,

    /// Secret derivation failed (Argon2id or BIP-39).
    #[error("derivation error: {0}")]
    DerivationError(String),
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;
