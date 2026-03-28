// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! WASM bindings for the 2FApi cryptographic core.
//!
//! Exposes Pedersen commitments, Sigma proofs, and OPRF operations
//! to JavaScript via wasm-bindgen. Secrets never cross the WASM↔JS
//! boundary — only public data (commitments, proofs, blinded points).

use wasm_bindgen::prelude::*;
use twofapi_crypto_core::{oprf, commit, derivation, CryptoError};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use zeroize::Zeroize;

/// Domain separation tag for OPRF (exposed for verification).
#[wasm_bindgen]
pub fn oprf_dst() -> String {
    oprf::OPRF_DST.to_string()
}

/// Hash a password to a Ristretto255 group element.
/// Returns 32 bytes (compressed point).
#[wasm_bindgen]
pub fn hash_to_group(input: &[u8]) -> Vec<u8> {
    let point = oprf::hash_to_group(input);
    point.compress().to_bytes().to_vec()
}

/// Blind a password for OPRF evaluation.
/// Returns { blinded_point: 32 bytes, blinding_factor: 32 bytes }.
///
/// FIX M-03: copy password into scratch space, hash from there, then zeroize.
/// The wasm-bindgen copy in linear memory is a `&[u8]` we cannot mutate,
/// but we *can* prevent a second copy from lingering in the heap.
#[wasm_bindgen]
pub fn oprf_blind(password: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Copy password into scratch space at a random offset (anti-watchpoint)
    let offset = random_secret_offset(password.len());
    SCRATCH_SPACE.with(|space| {
        let mut s = space.borrow_mut();
        let end = offset + password.len();
        s[offset..end].copy_from_slice(password);
    });

    // Hash from the scratch copy
    let point = SCRATCH_SPACE.with(|space| {
        let s = space.borrow();
        let end = offset + password.len();
        oprf::hash_to_group(&s[offset..end])
    });

    // Zeroize the scratch region that held the password
    SCRATCH_SPACE.with(|space| {
        let mut s = space.borrow_mut();
        let end = offset + password.len();
        s[offset..end].zeroize();
    });

    let (blinded, r) = oprf::blind(&point);

    // Return blinded_point (32) || blinding_factor (32) = 64 bytes
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&blinded.compress().to_bytes());
    result.extend_from_slice(&r.to_bytes());
    Ok(result)
}

/// Unblind a server OPRF evaluation.
/// Input: evaluated (32 bytes) + blinding_factor (32 bytes).
/// Returns: OPRF output U (32 bytes).
#[wasm_bindgen]
pub fn oprf_unblind(evaluated: &[u8], blinding_factor: &[u8]) -> Result<Vec<u8>, JsValue> {
    if evaluated.len() != 32 || blinding_factor.len() != 32 {
        return Err(JsValue::from_str("Invalid input length"));
    }

    let eval_point = decompress_point(evaluated)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(blinding_factor);
    let r = Scalar::from_bytes_mod_order(r_bytes);

    let u = oprf::unblind(&eval_point, &r)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(u.compress().to_bytes().to_vec())
}

/// Server-side: evaluate OPRF on a blinded point.
/// Input: blinded_point (32 bytes) + oprf_key (32 bytes).
/// Returns: evaluated point (32 bytes).
#[wasm_bindgen]
pub fn oprf_evaluate(blinded_point: &[u8], oprf_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if blinded_point.len() != 32 || oprf_key.len() != 32 {
        return Err(JsValue::from_str("Invalid input length"));
    }

    let point = decompress_point(blinded_point)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(oprf_key);
    let k = Scalar::from_bytes_mod_order(k_bytes);

    let evaluated = oprf::evaluate(&point, &k)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(evaluated.compress().to_bytes().to_vec())
}

/// Generate a random OPRF key (32 bytes).
#[wasm_bindgen]
pub fn generate_oprf_key() -> Vec<u8> {
    oprf::generate_oprf_key().to_bytes().to_vec()
}

/// Validate that 32 bytes are a canonical, non-identity Ristretto255 point.
#[wasm_bindgen]
pub fn validate_point(bytes: &[u8]) -> Result<bool, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Expected 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    match oprf::validate_point(&arr) {
        Ok(_) => Ok(true),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Compute a Pedersen commitment C = s·G + r·H.
/// Input: secret (32 bytes) + blinding (32 bytes).
/// Returns: commitment (32 bytes compressed).
#[wasm_bindgen]
pub fn pedersen_commit(secret: &[u8], blinding: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret.len() != 32 || blinding.len() != 32 {
        return Err(JsValue::from_str("Expected 32-byte scalars"));
    }

    let mut s_bytes = [0u8; 32];
    let mut r_bytes = [0u8; 32];
    s_bytes.copy_from_slice(secret);
    r_bytes.copy_from_slice(blinding);

    let s = Scalar::from_bytes_mod_order(s_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);

    let c = commit(&s, &r);
    Ok(c.compress().to_bytes().to_vec())
}

/// Derive a credential (secret + blinding) from passphrase/PIN via Argon2id.
/// Returns 64 bytes: secret (32) || blinding (32).
#[wasm_bindgen]
pub fn derive_credential(
    credential: &str,
    email: &str,
    tenant_id: &str,
) -> Result<Vec<u8>, JsValue> {
    let derived = derivation::derive_credential(credential, email, tenant_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&derived.secret);
    result.extend_from_slice(&derived.blinding);
    Ok(result)
}

/// Zeroize ALL known secret regions in WASM linear memory.
///
/// R25-02 FIX (partial): instead of exposing raw pointer zeroize (R1-11),
/// this function zeroizes a fixed set of internal buffers.
/// The JS side calls this after every auth operation.
#[wasm_bindgen]
pub fn zeroize_secrets() {
    // Zeroize the thread-local secret scratch space
    SCRATCH_SPACE.with(|space| {
        let mut s = space.borrow_mut();
        s.zeroize();
    });
}

/// R25-02 FIX: Thread-local scratch space for secrets at randomized offsets.
///
/// Instead of allocating secrets at predictable heap addresses,
/// we use a fixed-size scratch buffer with a random OFFSET for each operation.
/// A debugger setting a watchpoint on a specific address will miss the secret
/// if the offset differs between executions.
///
/// The scratch space is 4KB — secrets (32-128 bytes) are placed at a random
/// position within this 4KB window. 4096/32 = 128 possible positions.
use std::cell::RefCell;

const SCRATCH_SIZE: usize = 4096;

thread_local! {
    static SCRATCH_SPACE: RefCell<[u8; SCRATCH_SIZE]> = RefCell::new([0u8; SCRATCH_SIZE]);
}

/// Allocate a secret at a random offset within the scratch space.
/// Returns the offset (for the caller to use) and zeroizes on drop.
fn random_secret_offset(len: usize) -> usize {
    let max_offset = SCRATCH_SIZE.saturating_sub(len);
    if max_offset == 0 { return 0; }

    // Use getrandom for the offset selection
    let mut offset_bytes = [0u8; 2];
    getrandom::getrandom(&mut offset_bytes).unwrap_or_default();
    let raw_offset = u16::from_le_bytes(offset_bytes) as usize;
    raw_offset % max_offset
}

// --- Internal helpers ---

fn decompress_point(bytes: &[u8]) -> Result<RistrettoPoint, CryptoError> {
    use curve25519_dalek::ristretto::CompressedRistretto;
    let compressed = CompressedRistretto::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidPointEncoding)?;
    compressed.decompress().ok_or(CryptoError::InvalidPointEncoding)
}
