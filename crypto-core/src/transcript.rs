// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Fiat-Shamir transcript for non-interactive Sigma proofs.
//!
//! The transcript computes a challenge scalar from the public parameters:
//!   c = H(domain_sep || G || H || C || A || context)
//!
//! Where H is SHA-512 with reduction to a Ristretto255 scalar.
//! Domain separation prevents cross-protocol attacks.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Domain separation tag for the Fiat-Shamir transcript.
const TRANSCRIPT_DST: &[u8] = b"2FApi-Sigma-Transcript-v1";

/// Computes the Fiat-Shamir challenge from transcript bytes.
///
/// The input should be the concatenation of all public parameters:
/// G || H || C || A || context (nonce, channel binding, etc.)
///
/// The output is a scalar reduced modulo the group order l,
/// computed as SHA-512(DST || data) reduced to a Scalar.
pub fn hash_transcript(data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(TRANSCRIPT_DST);
    hasher.update(data);
    let hash_output = hasher.finalize();
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash_output);
    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

/// Computes the Fiat-Shamir challenge with explicit domain separation.
///
/// Allows callers to provide a custom domain separator for different
/// proof contexts (e.g., enrollment proof vs authentication proof).
pub fn hash_transcript_with_domain(domain: &[u8], data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(data);
    let hash_output = hasher.finalize();
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash_output);
    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

/// Returns the raw SHA-512 hash of transcript data (64 bytes).
/// Useful when the caller needs the full hash before scalar reduction.
pub fn hash_transcript_raw(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(TRANSCRIPT_DST);
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Returns the transcript hash as 32 bytes (the canonical scalar encoding).
/// This is the format expected by the TypeScript layer via napi.
pub fn hash_transcript_bytes(data: &[u8]) -> [u8; 32] {
    hash_transcript(data).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_transcript_is_deterministic() {
        let data = b"test transcript data";
        let h1 = hash_transcript(data);
        let h2 = hash_transcript(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_data_yields_different_hashes() {
        let h1 = hash_transcript(b"data1");
        let h2 = hash_transcript(b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_is_nonzero_for_nonempty_input() {
        let h = hash_transcript(b"nonempty");
        assert_ne!(h, Scalar::ZERO);
    }

    #[test]
    fn hash_transcript_bytes_has_correct_length() {
        let bytes = hash_transcript_bytes(b"test");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn custom_domain_differs_from_default() {
        let data = b"same data";
        let h_default = hash_transcript(data);
        let h_custom = hash_transcript_with_domain(b"custom-domain", data);
        assert_ne!(h_default, h_custom);
    }

    // --- Mutation testing killers ---

    #[test]
    fn hash_transcript_with_domain_is_deterministic() {
        let h1 = hash_transcript_with_domain(b"dom", b"data");
        let h2 = hash_transcript_with_domain(b"dom", b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_transcript_with_domain_is_nonzero() {
        let h = hash_transcript_with_domain(b"dom", b"data");
        assert_ne!(h, Scalar::ZERO);
    }

    #[test]
    fn hash_transcript_with_domain_different_domains_differ() {
        let h1 = hash_transcript_with_domain(b"dom-A", b"data");
        let h2 = hash_transcript_with_domain(b"dom-B", b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_transcript_raw_is_64_bytes() {
        let raw = hash_transcript_raw(b"test");
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn hash_transcript_raw_is_nonzero() {
        let raw = hash_transcript_raw(b"test");
        assert!(raw.iter().any(|&b| b != 0));
    }

    #[test]
    fn hash_transcript_raw_is_deterministic() {
        let r1 = hash_transcript_raw(b"test");
        let r2 = hash_transcript_raw(b"test");
        assert_eq!(r1, r2);
    }

    #[test]
    fn hash_transcript_raw_different_input_differs() {
        let r1 = hash_transcript_raw(b"input-A");
        let r2 = hash_transcript_raw(b"input-B");
        assert_ne!(r1, r2);
    }
}
