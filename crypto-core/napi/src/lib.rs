// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! napi-rs bindings for 2FApi crypto core.
//!
//! Exports Ristretto255 cryptographic operations to Node.js:
//! - Proof equation verification
//! - Transcript hashing (Fiat-Shamir)
//! - Element validation (canonical point/scalar, identity)
//! - Proof generation
//! - Pedersen commitment

use napi::bindgen_prelude::*;
use napi_derive::napi;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use twofapi_crypto_core as crypto;

/// Parameters for verifying the Sigma protocol equation.
#[napi(object)]
pub struct ProofEquationParams {
    /// Compressed Ristretto255 point G (32 bytes).
    pub generator_g: Buffer,
    /// Compressed Ristretto255 point H (32 bytes).
    pub generator_h: Buffer,
    /// Compressed commitment point C (32 bytes).
    pub commitment: Buffer,
    /// Compressed announcement point A (32 bytes).
    pub announcement: Buffer,
    /// Challenge scalar c (32 bytes, canonical).
    pub challenge: Buffer,
    /// Response scalar z_s (32 bytes, canonical).
    pub response_s: Buffer,
    /// Response scalar z_r (32 bytes, canonical).
    pub response_r: Buffer,
}

/// Parameters for generating a Sigma proof.
#[napi(object)]
pub struct ProofGenerationParams {
    /// Secret scalar s (32 bytes).
    pub secret: Buffer,
    /// Blinding scalar r (32 bytes).
    pub blinding: Buffer,
    /// Compressed commitment point C (32 bytes).
    pub commitment: Buffer,
    /// Compressed generator G (32 bytes).
    pub generator_g: Buffer,
    /// Compressed generator H (32 bytes).
    pub generator_h: Buffer,
    /// Transcript context bytes (variable length).
    pub transcript_data: Buffer,
}

/// Extracts exactly 32 bytes from a Buffer, returning an error if length is wrong.
fn extract_32_bytes(buf: &Buffer, name: &str) -> Result<[u8; 32]> {
    if buf.len() != 32 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be exactly 32 bytes, got {}", buf.len()),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(buf.as_ref());
    Ok(bytes)
}

/// Decodes a compressed Ristretto255 point from a Buffer.
fn decode_point(buf: &Buffer, name: &str) -> Result<RistrettoPoint> {
    let bytes = extract_32_bytes(buf, name)?;
    crypto::decompress_point(&bytes).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("invalid {name}: {e}"),
        )
    })
}

/// Decodes a canonical scalar from a Buffer.
fn decode_scalar_buf(buf: &Buffer, name: &str) -> Result<Scalar> {
    let bytes = extract_32_bytes(buf, name)?;
    crypto::decode_scalar(&bytes).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("invalid {name}: {e}"),
        )
    })
}

/// Verifies the Sigma protocol equation: z_s·G + z_r·H == A + c·C
///
/// Returns `true` if the equation holds, `false` otherwise.
/// Throws on invalid input encodings (non-canonical points/scalars).
#[napi]
pub fn verify_proof_equation(params: ProofEquationParams) -> Result<bool> {
    let g = decode_point(&params.generator_g, "generatorG")?;
    let h = decode_point(&params.generator_h, "generatorH")?;
    let commitment = decode_point(&params.commitment, "commitment")?;
    let announcement = decode_point(&params.announcement, "announcement")?;
    let challenge = decode_scalar_buf(&params.challenge, "challenge")?;
    let response_s = decode_scalar_buf(&params.response_s, "responseS")?;
    let response_r = decode_scalar_buf(&params.response_r, "responseR")?;

    Ok(crypto::verify_equation(
        &g,
        &h,
        &commitment,
        &announcement,
        &challenge,
        &response_s,
        &response_r,
    ))
}

/// Computes the Fiat-Shamir transcript hash.
///
/// Input: arbitrary-length transcript bytes.
/// Output: 32-byte canonical scalar (reduced modulo group order l).
#[napi]
pub fn hash_transcript(data: Buffer) -> Buffer {
    let result = crypto::hash_transcript_bytes(data.as_ref());
    Buffer::from(result.to_vec())
}

/// Checks whether 32 bytes are a canonical Ristretto255 point encoding.
///
/// Returns `false` for non-32-byte inputs instead of throwing.
#[napi]
pub fn is_canonical_point(bytes: Buffer) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes.as_ref());
    crypto::is_canonical_point(&arr)
}

/// Checks whether 32 bytes are a canonical scalar (reduced modulo l).
///
/// Returns `false` for non-32-byte inputs instead of throwing.
#[napi]
pub fn is_canonical_scalar(bytes: Buffer) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes.as_ref());
    crypto::is_canonical_scalar(&arr)
}

/// Checks whether 32 bytes encode the Ristretto255 identity element.
///
/// Returns `false` for non-32-byte inputs instead of throwing.
#[napi]
pub fn is_identity_point(bytes: Buffer) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes.as_ref());
    crypto::is_identity(&arr)
}

/// Generates a Sigma proof of knowledge of the Pedersen commitment opening.
///
/// Returns 96 bytes: announcement (32) || response_s (32) || response_r (32).
/// Ephemeral randomness is generated internally using OS randomness.
/// Secret and blinding scalars are zeroized after use.
#[napi]
pub fn generate_proof(params: ProofGenerationParams) -> Result<Buffer> {
    let mut secret = decode_scalar_buf(&params.secret, "secret")?;
    let mut blinding = decode_scalar_buf(&params.blinding, "blinding")?;
    let commitment = decode_point(&params.commitment, "commitment")?;
    let g = decode_point(&params.generator_g, "generatorG")?;
    let h = decode_point(&params.generator_h, "generatorH")?;

    // Generate ephemeral randomness
    let mut k_s_bytes = [0u8; 64];
    let mut k_r_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut k_s_bytes);
    OsRng.fill_bytes(&mut k_r_bytes);
    let randomness = crypto::ProofRandomness {
        k_s: Scalar::from_bytes_mod_order_wide(&k_s_bytes),
        k_r: Scalar::from_bytes_mod_order_wide(&k_r_bytes),
    };
    k_s_bytes.zeroize();
    k_r_bytes.zeroize();

    let proof = crypto::prove(
        &secret,
        &blinding,
        &randomness,
        &commitment,
        &g,
        &h,
        params.transcript_data.as_ref(),
    );

    // Zeroize secrets
    secret.zeroize();
    blinding.zeroize();

    let bytes = proof.to_bytes();
    Ok(Buffer::from(bytes.to_vec()))
}

/// Computes a Pedersen commitment C = s·G + r·H using the standard generators.
///
/// Input: secret (32 bytes), blinding (32 bytes).
/// Output: compressed commitment point (32 bytes).
#[napi]
pub fn commit(secret: Buffer, blinding: Buffer) -> Result<Buffer> {
    let mut s = decode_scalar_buf(&secret, "secret")?;
    let mut r = decode_scalar_buf(&blinding, "blinding")?;
    let point = crypto::commit(&s, &r);
    s.zeroize();
    r.zeroize();
    Ok(Buffer::from(point.compress().to_bytes().to_vec()))
}

/// Returns the compressed Ristretto255 basepoint G (32 bytes).
///
/// G is the standard Ristretto255 basepoint from curve25519-dalek.
#[napi]
pub fn get_generator_g() -> Buffer {
    Buffer::from(crypto::generators::generator_g().compress().to_bytes().to_vec())
}

/// Returns the compressed secondary generator H (32 bytes).
///
/// H is derived via hash-to-point with domain separator "2FApi-Pedersen-GeneratorH-v1".
/// The discrete log of H with respect to G is unknown.
#[napi]
pub fn get_generator_h() -> Buffer {
    Buffer::from(crypto::generators::generator_h().compress().to_bytes().to_vec())
}

/// Constant-time equality comparison using `subtle::ConstantTimeEq`.
///
/// Returns `false` for inputs of different lengths. The length check
/// itself is NOT constant-time (lengths are not secret), but no
/// byte-level comparison leaks timing information.
///
/// Never panics — returns `false` on any mismatch.
#[napi]
pub fn constant_time_eq(a: Buffer, b: Buffer) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_ref().ct_eq(b.as_ref()).into()
}
