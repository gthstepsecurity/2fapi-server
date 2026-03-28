// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Sigma protocol (Schnorr-like) for proving knowledge of a Pedersen opening.
//!
//! Proves knowledge of (s, r) such that C = s·G + r·H without revealing s or r.
//!
//! Protocol (Fiat-Shamir / non-interactive):
//! 1. Prover picks random k_s, k_r and computes announcement A = k_s·G + k_r·H
//! 2. Challenge c = H_transcript(G || H || C || A || context)
//! 3. Responses z_s = k_s + c·s, z_r = k_r + c·r
//! 4. Verifier checks: z_s·G + z_r·H == A + c·C

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{CryptoError, CryptoResult};
use crate::transcript;

/// A Sigma proof consisting of announcement A and responses (z_s, z_r).
/// The challenge c is recomputed by the verifier from the transcript.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Announcement point A = k_s·G + k_r·H (compressed).
    pub announcement: CompressedRistretto,
    /// Response scalar z_s = k_s + c·s.
    pub response_s: Scalar,
    /// Response scalar z_r = k_r + c·r.
    pub response_r: Scalar,
}

impl Proof {
    /// Serializes the proof to 96 bytes: A (32) || z_s (32) || z_r (32).
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut output = [0u8; 96];
        output[0..32].copy_from_slice(self.announcement.as_bytes());
        output[32..64].copy_from_slice(&self.response_s.to_bytes());
        output[64..96].copy_from_slice(&self.response_r.to_bytes());
        output
    }

    /// Deserializes a proof from 96 bytes.
    pub fn from_bytes(bytes: &[u8; 96]) -> CryptoResult<Self> {
        let announcement = CompressedRistretto::from_slice(&bytes[0..32])
            .map_err(|_| CryptoError::InvalidPointEncoding)?;

        let mut scalar_bytes = [0u8; 32];

        scalar_bytes.copy_from_slice(&bytes[32..64]);
        let response_s_opt = Scalar::from_canonical_bytes(scalar_bytes);
        if (!bool::from(response_s_opt.is_some())) {
            return Err(CryptoError::InvalidScalarEncoding);
        }
        let response_s = response_s_opt.unwrap();

        scalar_bytes.copy_from_slice(&bytes[64..96]);
        let response_r_opt = Scalar::from_canonical_bytes(scalar_bytes);
        if (!bool::from(response_r_opt.is_some())) {
            return Err(CryptoError::InvalidScalarEncoding);
        }
        let response_r = response_r_opt.unwrap();

        Ok(Self {
            announcement,
            response_s,
            response_r,
        })
    }
}

/// Ephemeral randomness for proof generation. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProofRandomness {
    /// Random scalar k_s for the secret component.
    pub k_s: Scalar,
    /// Random scalar k_r for the blinding component.
    pub k_r: Scalar,
}

/// Derives deterministic proof nonces using RFC 6979 hybrid approach (R16-01 fix).
///
/// Combines HMAC-based deterministic derivation (from the secret + context)
/// with OS randomness as ADDITIONAL entropy. If the CSPRNG is compromised
/// (state-level implant), the HMAC derivation alone provides unique nonces.
/// If the CSPRNG is healthy, the random bytes add extra unpredictability.
///
/// This protects against the Dual EC DRBG / Crypto AG scenario where a
/// nation-state adversary controls the OS random number generator.
pub fn derive_proof_nonces(
    secret: &Scalar,
    blinding: &Scalar,
    commitment: &RistrettoPoint,
    transcript_data: &[u8],
) -> ProofRandomness {
    use sha2::{Sha512, Digest};
    use rand::rngs::OsRng;
    use rand::RngCore;

    // Collect OS randomness (may be compromised — that's OK)
    let mut random_extra = [0u8; 32];
    OsRng.fill_bytes(&mut random_extra);

    // Deterministic component: HMAC-like construction from secret + context
    // k_s = SHA-512(secret || DST || commitment || transcript || random_extra)[..64] → scalar
    let mut hasher_s = Sha512::new();
    hasher_s.update(b"2fapi-sigma-nonce-ks-v1");
    hasher_s.update(&secret.to_bytes());
    hasher_s.update(&commitment.compress().to_bytes());
    hasher_s.update(transcript_data);
    hasher_s.update(&random_extra);
    let hash_s = hasher_s.finalize();
    let mut wide_s = [0u8; 64];
    wide_s.copy_from_slice(&hash_s);
    let k_s = Scalar::from_bytes_mod_order_wide(&wide_s);

    // k_r = SHA-512(blinding || DST || k_s || transcript || random_extra)[..64] → scalar
    let mut hasher_r = Sha512::new();
    hasher_r.update(b"2fapi-sigma-nonce-kr-v1");
    hasher_r.update(&blinding.to_bytes());
    hasher_r.update(&k_s.to_bytes());
    hasher_r.update(transcript_data);
    hasher_r.update(&random_extra);
    let hash_r = hasher_r.finalize();
    let mut wide_r = [0u8; 64];
    wide_r.copy_from_slice(&hash_r);
    let k_r = Scalar::from_bytes_mod_order_wide(&wide_r);

    // Zeroize intermediate material
    random_extra.zeroize();
    wide_s.zeroize();
    wide_r.zeroize();

    ProofRandomness { k_s, k_r }
}

/// Generates a Sigma proof of knowledge of the opening (s, r) of commitment C.
///
/// # Parameters
/// - `secret`: the secret scalar s
/// - `blinding`: the blinding scalar r
/// - `randomness`: ephemeral random scalars (k_s, k_r)
/// - `commitment`: the commitment point C = s·G + r·H
/// - `generator_g`: the primary generator G
/// - `generator_h`: the secondary generator H
/// - `transcript_data`: additional context bytes (nonce, channel binding, etc.)
///
/// # Returns
/// A `Proof` containing the announcement A and responses (z_s, z_r).
pub fn prove(
    secret: &Scalar,
    blinding: &Scalar,
    randomness: &ProofRandomness,
    commitment: &RistrettoPoint,
    generator_g: &RistrettoPoint,
    generator_h: &RistrettoPoint,
    transcript_data: &[u8],
) -> Proof {
    // Step 1: Compute announcement A = k_s·G + k_r·H
    // Use constant-time multiscalar_mul to protect secret randomness from timing leaks
    let announcement = RistrettoPoint::multiscalar_mul(
        [&randomness.k_s, &randomness.k_r],
        [*generator_g, *generator_h],
    );
    let announcement_compressed = announcement.compress();

    // Step 2: Compute Fiat-Shamir challenge
    // c = H(G || H || C || A || context)
    let challenge = compute_challenge(
        generator_g,
        generator_h,
        commitment,
        &announcement_compressed,
        transcript_data,
    );

    // Step 3: Compute responses
    // z_s = k_s + c·s
    // z_r = k_r + c·r
    let response_s = randomness.k_s + challenge * secret;
    let response_r = randomness.k_r + challenge * blinding;

    Proof {
        announcement: announcement_compressed,
        response_s,
        response_r,
    }
}

/// Verifies a Sigma proof against a commitment.
///
/// Checks: z_s·G + z_r·H == A + c·C
///
/// # Parameters
/// - `proof`: the proof to verify
/// - `commitment`: the commitment point C
/// - `generator_g`: the primary generator G
/// - `generator_h`: the secondary generator H
/// - `transcript_data`: the same context bytes used during proving
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
pub fn verify(
    proof: &Proof,
    commitment: &RistrettoPoint,
    generator_g: &RistrettoPoint,
    generator_h: &RistrettoPoint,
    transcript_data: &[u8],
) -> CryptoResult<bool> {
    // Decompress announcement
    let announcement = proof
        .announcement
        .decompress()
        .ok_or(CryptoError::InvalidPointEncoding)?;

    // Recompute challenge
    let challenge = compute_challenge(
        generator_g,
        generator_h,
        commitment,
        &proof.announcement,
        transcript_data,
    );

    // LHS: z_s·G + z_r·H
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        [&proof.response_s, &proof.response_r],
        [*generator_g, *generator_h],
    );

    // RHS: A + c·C
    let rhs = announcement + challenge * commitment;

    // Constant-time comparison
    let lhs_bytes = lhs.compress().to_bytes();
    let rhs_bytes = rhs.compress().to_bytes();
    Ok(bool::from(lhs_bytes.ct_eq(&rhs_bytes)))
}

/// Verifies the proof equation directly from raw components.
/// This is the function called by the napi layer.
///
/// Checks: z_s·G + z_r·H == A + c·C
pub fn verify_equation(
    generator_g: &RistrettoPoint,
    generator_h: &RistrettoPoint,
    commitment: &RistrettoPoint,
    announcement: &RistrettoPoint,
    challenge: &Scalar,
    response_s: &Scalar,
    response_r: &Scalar,
) -> bool {
    // Reject zero challenge: if c=0 the equation becomes z_s·G + z_r·H == A,
    // which is trivially satisfiable without knowledge of any secret.
    if *challenge == Scalar::ZERO {
        return false;
    }

    // Reject identity element as announcement to prevent trivially forged proofs
    if *announcement == RistrettoPoint::identity() {
        return false;
    }

    // Reject identity element as commitment — a proof against the identity
    // commitment is trivially forgeable (any z_s, z_r with A = z_s·G + z_r·H works).
    if *commitment == RistrettoPoint::identity() {
        return false;
    }

    // LHS: z_s·G + z_r·H
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        [response_s, response_r],
        [*generator_g, *generator_h],
    );

    // RHS: A + c·C
    let rhs = *announcement + challenge * commitment;

    // Constant-time comparison
    let lhs_bytes = lhs.compress().to_bytes();
    let rhs_bytes = rhs.compress().to_bytes();
    bool::from(lhs_bytes.ct_eq(&rhs_bytes))
}

/// Computes the Fiat-Shamir challenge scalar.
///
/// # WARNING — NOT production-authoritative
///
/// This function uses a DIFFERENT transcript format than the canonical TypeScript
/// implementation (`Transcript.build()` in `src/zk-verification/domain/model/transcript.ts`).
///
/// Differences:
/// - This function prepends `G || H || C || A` as raw bytes without length-prefixing
/// - The TypeScript version length-prefixes ALL fields with 4-byte big-endian u32
/// - The TypeScript version includes tag, clientId, nonce, channelBinding as separate fields
///
/// In production, the NAPI `hash_transcript` binding accepts the TypeScript-serialized
/// transcript bytes and hashes them. This Rust function is only used for internal tests.
///
/// See `docs/PROTOCOL.md` for the canonical transcript specification.
fn compute_challenge(
    generator_g: &RistrettoPoint,
    generator_h: &RistrettoPoint,
    commitment: &RistrettoPoint,
    announcement: &CompressedRistretto,
    transcript_data: &[u8],
) -> Scalar {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(generator_g.compress().as_bytes());
    transcript.extend_from_slice(generator_h.compress().as_bytes());
    transcript.extend_from_slice(commitment.compress().as_bytes());
    transcript.extend_from_slice(announcement.as_bytes());
    transcript.extend_from_slice(transcript_data);
    crate::transcript::hash_transcript(&transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators;
    use crate::pedersen;
    use curve25519_dalek::traits::Identity;
    use rand::rngs::OsRng;

    fn random_scalar() -> Scalar {
        let mut bytes = [0u8; 64];
        use rand::RngCore;
        OsRng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[test]
    fn valid_proof_verifies() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let randomness = ProofRandomness {
            k_s: random_scalar(),
            k_r: random_scalar(),
        };
        let context = b"test-context";

        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, context);
        let result = verify(&proof, &commitment, &g, &h, context).unwrap();
        assert!(result);
    }

    #[test]
    fn proof_with_wrong_secret_fails() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let wrong_s = random_scalar();
        let randomness = ProofRandomness {
            k_s: random_scalar(),
            k_r: random_scalar(),
        };
        let context = b"test-context";

        let proof = prove(&wrong_s, &r, &randomness, &commitment, &g, &h, context);
        let result = verify(&proof, &commitment, &g, &h, context).unwrap();
        assert!(!result);
    }

    #[test]
    fn proof_with_wrong_context_fails() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let randomness = ProofRandomness {
            k_s: random_scalar(),
            k_r: random_scalar(),
        };

        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, b"context-A");
        let result = verify(&proof, &commitment, &g, &h, b"context-B").unwrap();
        assert!(!result);
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let randomness = ProofRandomness {
            k_s: random_scalar(),
            k_r: random_scalar(),
        };

        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, b"roundtrip");
        let bytes = proof.to_bytes();
        let recovered = Proof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.announcement, recovered.announcement);
        assert_eq!(proof.response_s, recovered.response_s);
        assert_eq!(proof.response_r, recovered.response_r);
    }

    #[test]
    fn verify_equation_rejects_identity_announcement() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let identity = RistrettoPoint::identity();
        let challenge = random_scalar();
        let response_s = random_scalar();
        let response_r = random_scalar();

        let result = verify_equation(
            &g,
            &h,
            &commitment,
            &identity,
            &challenge,
            &response_s,
            &response_r,
        );
        assert!(!result, "verify_equation must reject identity element as announcement");
    }

    #[test]
    fn verify_equation_direct() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let randomness = ProofRandomness {
            k_s: random_scalar(),
            k_r: random_scalar(),
        };
        let context = b"equation-test";

        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, context);
        let announcement = proof.announcement.decompress().unwrap();

        // Recompute challenge
        let mut transcript = Vec::new();
        transcript.extend_from_slice(g.compress().as_bytes());
        transcript.extend_from_slice(h.compress().as_bytes());
        transcript.extend_from_slice(commitment.compress().as_bytes());
        transcript.extend_from_slice(proof.announcement.as_bytes());
        transcript.extend_from_slice(context);
        let challenge = crate::transcript::hash_transcript(&transcript);

        let result = verify_equation(
            &g,
            &h,
            &commitment,
            &announcement,
            &challenge,
            &proof.response_s,
            &proof.response_r,
        );
        assert!(result);
    }

    // --- Additional tests for comprehensive coverage ---

    #[test]
    fn proof_with_wrong_blinding_fails() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let wrong_r = random_scalar();
        let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
        let proof = prove(&s, &wrong_r, &randomness, &commitment, &g, &h, b"ctx");
        assert!(!verify(&proof, &commitment, &g, &h, b"ctx").unwrap());
    }

    #[test]
    fn proof_nonmalleability_single_bit_flip() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, b"malleable");

        // Flip one bit in response_s
        let mut tampered_bytes = proof.to_bytes();
        tampered_bytes[32] ^= 0x01;
        if let Ok(tampered) = Proof::from_bytes(&tampered_bytes) {
            let result = verify(&tampered, &commitment, &g, &h, b"malleable").unwrap();
            assert!(!result, "flipping one bit in proof must invalidate it");
        }
    }

    #[test]
    fn proof_against_identity_commitment_rejected() {
        let (g, h) = generators::generators();
        let identity = RistrettoPoint::identity();
        let s = random_scalar();
        let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
        let proof = prove(&s, &Scalar::ZERO, &randomness, &identity, &g, &h, b"id");
        let result = verify(&proof, &identity, &g, &h, b"id");
        // Verification should either fail or reject identity commitment
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn verify_equation_rejects_zero_challenge() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let announcement = random_scalar() * g + random_scalar() * h;
        let result = verify_equation(&g, &h, &commitment, &announcement, &Scalar::ZERO, &random_scalar(), &random_scalar());
        assert!(!result, "zero challenge must be rejected");
    }

    #[test]
    fn verify_equation_rejects_identity_commitment() {
        let (g, h) = generators::generators();
        let identity = RistrettoPoint::identity();
        let result = verify_equation(&g, &h, &identity, &(random_scalar() * g), &random_scalar(), &random_scalar(), &random_scalar());
        assert!(!result, "identity commitment must be rejected");
    }

    #[test]
    fn multiple_proofs_for_same_commitment_all_verify() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        for i in 0..10 {
            let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
            let ctx = format!("proof-{}", i);
            let proof = prove(&s, &r, &randomness, &commitment, &g, &h, ctx.as_bytes());
            assert!(verify(&proof, &commitment, &g, &h, ctx.as_bytes()).unwrap(),
                "proof {} must verify", i);
        }
    }

    #[test]
    fn proof_with_different_generators_fails() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, b"gen");

        // Verify with swapped generators
        let result = verify(&proof, &commitment, &h, &g, b"gen").unwrap();
        assert!(!result, "swapped generators must invalidate proof");
    }

    #[test]
    fn derive_proof_nonces_produces_nonzero_scalars() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let nonces = derive_proof_nonces(&s, &r, &commitment, b"context");
        assert_ne!(nonces.k_s, Scalar::ZERO);
        assert_ne!(nonces.k_r, Scalar::ZERO);
    }

    #[test]
    fn derive_proof_nonces_different_contexts_produce_different_nonces() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);

        let n1 = derive_proof_nonces(&s, &r, &commitment, b"context-1");
        let n2 = derive_proof_nonces(&s, &r, &commitment, b"context-2");
        assert_ne!(n1.k_s, n2.k_s, "different contexts must produce different nonces");
    }

    #[test]
    fn proof_with_derived_nonces_verifies() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let nonces = derive_proof_nonces(&s, &r, &commitment, b"rfc6979");
        let proof = prove(&s, &r, &nonces, &commitment, &g, &h, b"rfc6979");
        assert!(verify(&proof, &commitment, &g, &h, b"rfc6979").unwrap());
    }

    #[test]
    fn invalid_proof_bytes_rejected() {
        let garbage = [0xFFu8; 96];
        // from_bytes should either fail or produce an unverifiable proof
        if let Ok(proof) = Proof::from_bytes(&garbage) {
            let (g, h) = generators::generators();
            let commitment = pedersen::commit_with_generators(&random_scalar(), &random_scalar(), &g, &h);
            let result = verify(&proof, &commitment, &g, &h, b"garbage");
            assert!(result.is_err() || !result.unwrap());
        }
    }

    #[test]
    fn proof_is_96_bytes() {
        let (g, h) = generators::generators();
        let s = random_scalar();
        let r = random_scalar();
        let commitment = pedersen::commit_with_generators(&s, &r, &g, &h);
        let randomness = ProofRandomness { k_s: random_scalar(), k_r: random_scalar() };
        let proof = prove(&s, &r, &randomness, &commitment, &g, &h, b"size");
        assert_eq!(proof.to_bytes().len(), 96);
    }
}
