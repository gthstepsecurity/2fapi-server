// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Secret derivation from passphrase or PIN via Argon2id.
//!
//! Derives a Pedersen commitment opening (secret s, blinding r) from:
//! - A 4-word BIP-39 passphrase, OR
//! - A 6-digit numeric PIN
//!
//! The derivation is deterministic: same input → same (s, r) → same commitment C.
//! This allows any device to derive the same secret without syncing.
//!
//! ## Security: Enrollment Pepper (R13-01 fix)
//!
//! The Argon2id salt includes an optional `enrollment_pepper` (server-side secret).
//! Without the pepper, an attacker who reads the public commitment C cannot
//! brute-force the passphrase offline — the salt is unpredictable.
//! The pepper is stored in HSM and provided to the client during enrollment
//! via a secure channel (distinct from the OPRF key).
//!
//! Argon2id parameters are chosen for ~500ms on modern hardware:
//! - Memory: 64 MB
//! - Iterations: 3
//! - Parallelism: 1
//! - Output: 64 bytes (split into s and r, each 32 bytes → reduced mod group order)

use argon2::{Argon2, Algorithm, Version, Params};
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{CryptoError, CryptoResult};

/// Argon2id parameters for passphrase/PIN derivation.
const ARGON2_MEMORY_KB: u32 = 65_536;  // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 64;   // 64 bytes → split into s (32) + r (32)

/// Domain separation tag for the salt derivation.
const SALT_DST: &[u8] = b"2FApi-Argon2id-Salt-v1";

/// A derived credential (secret + blinding) with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedCredential {
    /// The secret scalar s (32 bytes, canonical).
    pub secret: [u8; 32],
    /// The blinding scalar r (32 bytes, canonical).
    pub blinding: [u8; 32],
}

/// Derives a (secret, blinding) pair from a passphrase or PIN.
///
/// The salt is deterministically derived from `email`, `tenant_id`,
/// and an optional `enrollment_pepper` (server-side secret).
///
/// # Parameters
/// - `credential`: the passphrase (4 words joined by spaces) or PIN (6 digits)
/// - `email`: the user's email (part of the deterministic salt)
/// - `tenant_id`: the tenant identifier (part of the deterministic salt)
///
/// # Returns
/// A `DerivedCredential` containing the secret and blinding scalars.
/// Both are reduced modulo the group order (canonical).
pub fn derive_credential(
    credential: &str,
    email: &str,
    tenant_id: &str,
) -> CryptoResult<DerivedCredential> {
    derive_credential_with_pepper(credential, email, tenant_id, &[])
}

/// Derives a (secret, blinding) pair with an enrollment pepper.
///
/// The enrollment pepper is a server-side secret that prevents offline
/// brute-force against the public Pedersen commitment (R13-01 fix).
/// Without the pepper, an attacker cannot compute candidate (s, r)
/// from the passphrase alone — the commitment becomes an opaque value.
///
/// # Parameters
/// - `credential`: the passphrase or PIN
/// - `email`: the user's email
/// - `tenant_id`: the tenant identifier
/// - `enrollment_pepper`: server-side secret (empty = backward-compatible)
pub fn derive_credential_with_pepper(
    credential: &str,
    email: &str,
    tenant_id: &str,
    enrollment_pepper: &[u8],
) -> CryptoResult<DerivedCredential> {
    // Build salt: SHA-512(DST || email || tenant_id || pepper)
    // The pepper makes the salt unpredictable to offline attackers.
    use sha2::{Sha512, Digest};
    let mut salt_hasher = Sha512::new();
    salt_hasher.update(SALT_DST);
    salt_hasher.update(email.as_bytes());
    salt_hasher.update(b"||");
    salt_hasher.update(tenant_id.as_bytes());
    if !enrollment_pepper.is_empty() {
        salt_hasher.update(b"||");
        salt_hasher.update(enrollment_pepper);
    }
    let salt_hash = salt_hasher.finalize();
    // Argon2 salt must be at least 8 bytes; we use the first 16
    let salt = &salt_hash[..16];

    // Configure Argon2id
    let params = Params::new(
        ARGON2_MEMORY_KB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    ).map_err(|_| CryptoError::DerivationError("invalid Argon2id parameters".into()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive 64 bytes
    let mut output = [0u8; ARGON2_OUTPUT_LEN];
    argon2.hash_password_into(credential.as_bytes(), salt, &mut output)
        .map_err(|_| CryptoError::DerivationError("Argon2id derivation failed".into()))?;

    // Split into two 32-byte halves and reduce mod group order
    let s_wide = &output[..32];
    let r_wide = &output[32..64];

    // Use from_bytes_mod_order to get canonical scalars
    let mut s_bytes = [0u8; 32];
    let mut r_bytes = [0u8; 32];
    s_bytes.copy_from_slice(s_wide);
    r_bytes.copy_from_slice(r_wide);

    let s_scalar = Scalar::from_bytes_mod_order(s_bytes);
    let r_scalar = Scalar::from_bytes_mod_order(r_bytes);

    // Zeroize intermediate material
    output.zeroize();

    Ok(DerivedCredential {
        secret: s_scalar.to_bytes(),
        blinding: r_scalar.to_bytes(),
    })
}

/// Domain separation tag for the OPRF-enhanced derivation.
const OPRF_DERIVATION_DST: &[u8] = b"2FApi-OPRF-Credential-Derivation-v1";

/// Derives a (secret, blinding) pair using the double-lock OPRF pattern (R14-01 fix).
///
/// Combines two independent derivation paths:
///   1. Argon2id(passphrase, salt) → local_key (client-only, memory-hard)
///   2. OPRF(enrollment_key, passphrase) → oprf_output (requires server HSM)
///   3. (s, r) = HKDF(local_key || oprf_output, DST)
///
/// Neither the passphrase alone NOR the server alone can derive (s, r).
/// The enrollment OPRF key never leaves the HSM. The passphrase never reaches the server.
/// The public commitment C = s·G + r·H cannot be brute-forced without BOTH.
///
/// # Parameters
/// - `credential`: the passphrase or PIN
/// - `email`: the user's email
/// - `tenant_id`: the tenant identifier
/// - `oprf_output`: the unblinded OPRF result U = enrollment_key · hash_to_group(passphrase)
///                   (32 bytes, compressed Ristretto point)
pub fn derive_credential_with_oprf(
    credential: &str,
    email: &str,
    tenant_id: &str,
    oprf_output: &[u8; 32],
) -> CryptoResult<DerivedCredential> {
    use sha2::{Sha512, Digest};

    // Path 1: Argon2id (client-side, memory-hard, anti-brute-force)
    let mut salt_hasher = Sha512::new();
    salt_hasher.update(SALT_DST);
    salt_hasher.update(email.as_bytes());
    salt_hasher.update(b"||");
    salt_hasher.update(tenant_id.as_bytes());
    let salt_hash = salt_hasher.finalize();
    let salt = &salt_hash[..16];

    let params = Params::new(
        ARGON2_MEMORY_KB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    ).map_err(|_| CryptoError::DerivationError("invalid Argon2id parameters".into()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut argon2_output = [0u8; ARGON2_OUTPUT_LEN];
    argon2.hash_password_into(credential.as_bytes(), salt, &mut argon2_output)
        .map_err(|_| CryptoError::DerivationError("Argon2id derivation failed".into()))?;

    // Path 2: OPRF output (server-side, zero-knowledge, HSM-protected)
    // oprf_output = enrollment_key · hash_to_group(passphrase)
    // The client received this via the OPRF blind/evaluate/unblind protocol.

    // R18-02 FIX: Proper HKDF-SHA512 (RFC 5869) instead of raw SHA-512.
    // HKDF provides formal key derivation guarantees (Krawczyk 2010)
    // and is required for FIPS 140-3 / CC EAL4+ certification.
    let mut ikm = [0u8; 96]; // 64 (argon2) + 32 (oprf)
    ikm[..64].copy_from_slice(&argon2_output);
    ikm[64..96].copy_from_slice(oprf_output);

    let hk = hkdf::Hkdf::<Sha512>::new(Some(OPRF_DERIVATION_DST), &ikm);
    let mut hkdf_output = [0u8; 64];
    hk.expand(b"2fapi-credential-expand-v1", &mut hkdf_output)
        .map_err(|_| CryptoError::DerivationError("HKDF expansion failed".into()))?;

    // Zeroize intermediate material
    argon2_output.zeroize();
    ikm.zeroize();

    // Split into s (32 bytes) and r (32 bytes), reduce mod group order
    let mut s_bytes = [0u8; 32];
    let mut r_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&hkdf_output[..32]);
    r_bytes.copy_from_slice(&hkdf_output[32..64]);

    let s_scalar = Scalar::from_bytes_mod_order(s_bytes);
    let r_scalar = Scalar::from_bytes_mod_order(r_bytes);

    Ok(DerivedCredential {
        secret: s_scalar.to_bytes(),
        blinding: r_scalar.to_bytes(),
    })
}

/// Validates that a passphrase has exactly 4 BIP-39 words.
pub fn validate_passphrase(passphrase: &str) -> Result<[&str; 4], &'static str> {
    let words: Vec<&str> = passphrase.split_whitespace().collect();
    if words.len() != 4 {
        return Err("passphrase must be exactly 4 words");
    }

    // Check all words are in BIP-39 wordlist
    for word in &words {
        if crate::bip39::index_of(word).is_none() {
            return Err("word not in BIP-39 wordlist");
        }
    }

    // Check all words are different
    let mut sorted = words.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != 4 {
        return Err("all 4 words must be different");
    }

    Ok([words[0], words[1], words[2], words[3]])
}

/// Validates that a PIN is exactly 6 digits.
pub fn validate_pin(pin: &str) -> Result<(), &'static str> {
    if pin.len() != 6 {
        return Err("PIN must be exactly 6 digits");
    }
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must contain only digits");
    }
    // Reject trivial PINs
    let bytes = pin.as_bytes();
    let all_same = bytes.iter().all(|&b| b == bytes[0]);
    if all_same {
        return Err("PIN must not be all the same digit");
    }
    // Reject sequential PINs (123456, 654321)
    if pin == "123456" || pin == "654321" || pin == "000000" {
        return Err("PIN is too common");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_credential_is_deterministic() {
        let c1 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let c2 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        assert_eq!(c1.secret, c2.secret);
        assert_eq!(c1.blinding, c2.blinding);
    }

    #[test]
    fn different_passphrase_produces_different_secret() {
        let c1 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let c2 = derive_credential("red ocean calm star", "alice@acme.com", "tenant-1").unwrap();
        assert_ne!(c1.secret, c2.secret);
    }

    #[test]
    fn different_email_produces_different_secret() {
        let c1 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let c2 = derive_credential("blue tiger fast moon", "bob@acme.com", "tenant-1").unwrap();
        assert_ne!(c1.secret, c2.secret);
    }

    #[test]
    fn different_tenant_produces_different_secret() {
        let c1 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let c2 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-2").unwrap();
        assert_ne!(c1.secret, c2.secret);
    }

    #[test]
    fn pin_derivation_works() {
        let c = derive_credential("847291", "bob@acme.com", "tenant-1").unwrap();
        assert_ne!(c.secret, [0u8; 32]);
        assert_ne!(c.blinding, [0u8; 32]);
    }

    #[test]
    fn derived_scalars_are_non_zero() {
        let c = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        assert_ne!(c.secret, [0u8; 32]);
        assert_ne!(c.blinding, [0u8; 32]);
    }

    #[test]
    fn derived_commitment_is_reproducible() {
        let c = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let s = Scalar::from_bytes_mod_order(c.secret);
        let r = Scalar::from_bytes_mod_order(c.blinding);
        let commitment1 = crate::commit(&s, &r);

        let c2 = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let s2 = Scalar::from_bytes_mod_order(c2.secret);
        let r2 = Scalar::from_bytes_mod_order(c2.blinding);
        let commitment2 = crate::commit(&s2, &r2);

        assert_eq!(commitment1.compress(), commitment2.compress());
    }

    // --- Passphrase validation ---

    // --- Enrollment pepper (R13-01) ---

    #[test]
    fn derive_with_pepper_differs_from_without_pepper() {
        let without = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let with = derive_credential_with_pepper("blue tiger fast moon", "alice@acme.com", "tenant-1", b"server-secret-pepper").unwrap();
        assert_ne!(without.secret, with.secret, "pepper must change the derivation");
        assert_ne!(without.blinding, with.blinding);
    }

    #[test]
    fn derive_with_pepper_is_deterministic() {
        let c1 = derive_credential_with_pepper("blue tiger fast moon", "a@a.com", "t1", b"pepper").unwrap();
        let c2 = derive_credential_with_pepper("blue tiger fast moon", "a@a.com", "t1", b"pepper").unwrap();
        assert_eq!(c1.secret, c2.secret);
        assert_eq!(c1.blinding, c2.blinding);
    }

    #[test]
    fn different_peppers_produce_different_secrets() {
        let c1 = derive_credential_with_pepper("blue tiger fast moon", "a@a.com", "t1", b"pepper-A").unwrap();
        let c2 = derive_credential_with_pepper("blue tiger fast moon", "a@a.com", "t1", b"pepper-B").unwrap();
        assert_ne!(c1.secret, c2.secret);
    }

    #[test]
    fn empty_pepper_matches_legacy_derive_credential() {
        let legacy = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let with_empty = derive_credential_with_pepper("blue tiger fast moon", "alice@acme.com", "tenant-1", &[]).unwrap();
        assert_eq!(legacy.secret, with_empty.secret, "empty pepper must be backward-compatible");
        assert_eq!(legacy.blinding, with_empty.blinding);
    }

    // --- OPRF-based credential derivation (R14-01 double-lock) ---

    #[test]
    fn derive_with_oprf_produces_nonzero_secret() {
        let oprf_output = [0xAAu8; 32];
        let c = derive_credential_with_oprf("blue tiger fast moon", "alice@acme.com", "tenant-1", &oprf_output).unwrap();
        assert_ne!(c.secret, [0u8; 32]);
        assert_ne!(c.blinding, [0u8; 32]);
    }

    #[test]
    fn derive_with_oprf_is_deterministic() {
        let oprf = [0xBBu8; 32];
        let c1 = derive_credential_with_oprf("blue tiger fast moon", "a@a.com", "t1", &oprf).unwrap();
        let c2 = derive_credential_with_oprf("blue tiger fast moon", "a@a.com", "t1", &oprf).unwrap();
        assert_eq!(c1.secret, c2.secret);
        assert_eq!(c1.blinding, c2.blinding);
    }

    #[test]
    fn derive_with_oprf_differs_from_legacy() {
        let oprf = [0xCCu8; 32];
        let legacy = derive_credential("blue tiger fast moon", "alice@acme.com", "tenant-1").unwrap();
        let with_oprf = derive_credential_with_oprf("blue tiger fast moon", "alice@acme.com", "tenant-1", &oprf).unwrap();
        assert_ne!(legacy.secret, with_oprf.secret, "OPRF derivation must differ from legacy");
    }

    #[test]
    fn derive_with_oprf_different_oprf_outputs_produce_different_secrets() {
        let c1 = derive_credential_with_oprf("same", "a@a.com", "t1", &[0xAAu8; 32]).unwrap();
        let c2 = derive_credential_with_oprf("same", "a@a.com", "t1", &[0xBBu8; 32]).unwrap();
        assert_ne!(c1.secret, c2.secret, "different OPRF outputs must produce different secrets");
    }

    #[test]
    fn derive_with_oprf_different_passphrase_same_oprf_produces_different_secrets() {
        let oprf = [0xAAu8; 32];
        let c1 = derive_credential_with_oprf("blue tiger fast moon", "a@a.com", "t1", &oprf).unwrap();
        let c2 = derive_credential_with_oprf("red ocean calm star", "a@a.com", "t1", &oprf).unwrap();
        assert_ne!(c1.secret, c2.secret, "different passphrases must produce different secrets even with same OPRF");
    }

    #[test]
    fn derive_with_oprf_commitment_cannot_be_brute_forced_without_oprf() {
        // The attacker has the commitment C and the passphrase, but NOT the OPRF output.
        // They try derive_credential (legacy, no OPRF) and check against C.
        // The result MUST differ from the OPRF-derived commitment.
        let oprf = [0xDDu8; 32];
        let real = derive_credential_with_oprf("blue tiger fast moon", "a@a.com", "t1", &oprf).unwrap();
        let brute = derive_credential("blue tiger fast moon", "a@a.com", "t1").unwrap();

        // The attacker's brute-force guess (without OPRF) does NOT match
        assert_ne!(real.secret, brute.secret, "without OPRF output, commitment oracle is defeated");
    }

    // --- Passphrase validation ---

    #[test]
    fn validate_passphrase_accepts_valid() {
        assert!(validate_passphrase("abandon ability able about").is_ok());
    }

    #[test]
    fn validate_passphrase_rejects_too_few_words() {
        assert!(validate_passphrase("abandon ability able").is_err());
    }

    #[test]
    fn validate_passphrase_rejects_too_many_words() {
        assert!(validate_passphrase("abandon ability able about above").is_err());
    }

    #[test]
    fn validate_passphrase_rejects_non_bip39_word() {
        assert!(validate_passphrase("abandon ability xylophone about").is_err());
    }

    #[test]
    fn validate_passphrase_rejects_duplicate_words() {
        assert!(validate_passphrase("abandon abandon ability able").is_err());
    }

    // --- PIN validation ---

    #[test]
    fn validate_pin_accepts_valid() {
        assert!(validate_pin("847291").is_ok());
    }

    #[test]
    fn validate_pin_rejects_too_short() {
        assert!(validate_pin("8472").is_err());
    }

    #[test]
    fn validate_pin_rejects_non_numeric() {
        assert!(validate_pin("abc123").is_err());
    }

    #[test]
    fn validate_pin_rejects_all_same() {
        assert!(validate_pin("111111").is_err());
    }

    #[test]
    fn validate_pin_rejects_sequential() {
        assert!(validate_pin("123456").is_err());
    }

    #[test]
    fn validate_pin_accepts_with_leading_zeros() {
        assert!(validate_pin("007842").is_ok());
    }
}
