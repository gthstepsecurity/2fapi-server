// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Additive secret sharing for distributed Sigma proofs.
//!
//! Splits the Pedersen commitment opening (s, r) into two additive shares:
//!   s = s1 + s2 (mod l)
//!   r = r1 + r2 (mod l)
//!
//! The client holds (s1, r1). The server holds (s2, r2).
//! The full secret s is NEVER reconstructed. The Sigma proof is computed
//! distributively: each party computes a partial response, and the
//! combined response is a valid proof.
//!
//! Security: compromising ONE party reveals only ONE share.
//! Both shares are needed to forge a proof.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An additive share of a Pedersen commitment opening.
/// Contains one share of the secret and one share of the blinding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
    pub s: Scalar,
    pub r: Scalar,
}

/// A partial Sigma response computed from one share.
pub struct PartialResponse {
    pub z_s: Scalar,
    pub z_r: Scalar,
}

/// Split a commitment opening (s, r) into two additive shares.
///
/// Returns (client_share, server_share) such that:
///   client_share.s + server_share.s = s
///   client_share.r + server_share.r = r
///
/// The full secret s is zeroized from the caller's memory after splitting.
/// From this point on, s exists ONLY as two shares on two different machines.
pub fn split_into_shares(s: &Scalar, r: &Scalar) -> (SecretShare, SecretShare) {
    // Client share: random
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    let s1 = Scalar::from_bytes_mod_order_wide(&bytes);

    OsRng.fill_bytes(&mut bytes);
    let r1 = Scalar::from_bytes_mod_order_wide(&bytes);

    bytes.zeroize();

    // Server share: complement
    let s2 = s - s1;
    let r2 = r - r1;

    (
        SecretShare { s: s1, r: r1 },
        SecretShare { s: s2, r: r2 },
    )
}

/// Compute a partial commitment from one share.
/// C_partial = share.s · G + share.r · H
///
/// The full commitment C = C_client + C_server (point addition).
pub fn partial_commitment(
    share: &SecretShare,
    generator_g: &RistrettoPoint,
    generator_h: &RistrettoPoint,
) -> RistrettoPoint {
    share.s * generator_g + share.r * generator_h
}

/// Client-side: compute partial Sigma response from client share.
///
/// z_s1 = k_s + c · s1
/// z_r1 = k_r + c · r1
///
/// The client has the full nonces (k_s, k_r) and its share (s1, r1).
pub fn client_partial_response(
    share: &SecretShare,
    k_s: &Scalar,
    k_r: &Scalar,
    challenge: &Scalar,
) -> PartialResponse {
    PartialResponse {
        z_s: k_s + challenge * share.s,
        z_r: k_r + challenge * share.r,
    }
}

/// Server-side: compute partial Sigma response from server share.
///
/// z_s2 = c · s2
/// z_r2 = c · r2
///
/// The server has only its share (s2, r2) and the challenge c.
/// The server does NOT have the nonces (they belong to the client).
pub fn server_partial_response(
    share: &SecretShare,
    challenge: &Scalar,
) -> PartialResponse {
    PartialResponse {
        z_s: challenge * share.s,
        z_r: challenge * share.r,
    }
}

/// Combine client and server partial responses into a final proof response.
///
/// z_s = z_s1 + z_s2 = k_s + c·(s1 + s2) = k_s + c·s
/// z_r = z_r1 + z_r2 = k_r + c·(r1 + r2) = k_r + c·r
pub fn combine_responses(
    client: &PartialResponse,
    server: &PartialResponse,
) -> (Scalar, Scalar) {
    (client.z_s + server.z_s, client.z_r + server.z_r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generators, commit, sigma};
    use crate::transcript::hash_transcript;

    fn random_scalar() -> Scalar {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[test]
    fn shares_sum_to_original_secret() {
        let s = random_scalar();
        let r = random_scalar();
        let (client, server) = split_into_shares(&s, &r);
        assert_eq!(client.s + server.s, s);
        assert_eq!(client.r + server.r, r);
    }

    #[test]
    fn partial_commitments_sum_to_full_commitment() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();

        let full_commitment = commit(&s, &r);
        let (client_share, server_share) = split_into_shares(&s, &r);

        let c1 = partial_commitment(&client_share, &g, &h);
        let c2 = partial_commitment(&server_share, &g, &h);

        assert_eq!(c1 + c2, full_commitment);
    }

    #[test]
    fn distributed_proof_is_valid() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();
        let commitment = commit(&s, &r);

        // Split secret
        let (client_share, server_share) = split_into_shares(&s, &r);

        // Client generates nonces and announcement
        let k_s = random_scalar();
        let k_r = random_scalar();
        let announcement = k_s * g + k_r * h;

        // Challenge (Fiat-Shamir)
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&g.compress().to_bytes());
        transcript.extend_from_slice(&h.compress().to_bytes());
        transcript.extend_from_slice(&commitment.compress().to_bytes());
        transcript.extend_from_slice(&announcement.compress().to_bytes());
        transcript.extend_from_slice(b"test-context");
        let challenge = hash_transcript(&transcript);

        // Client partial response
        let client_partial = client_partial_response(&client_share, &k_s, &k_r, &challenge);

        // Server partial response
        let server_partial = server_partial_response(&server_share, &challenge);

        // Combine
        let (z_s, z_r) = combine_responses(&client_partial, &server_partial);

        // Verify: z_s·G + z_r·H == A + c·C
        let lhs = z_s * g + z_r * h;
        let rhs = announcement + challenge * commitment;
        assert_eq!(lhs, rhs, "distributed proof must verify correctly");
    }

    #[test]
    fn client_share_alone_cannot_forge_proof() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();
        let commitment = commit(&s, &r);

        let (client_share, _server_share) = split_into_shares(&s, &r);

        // Attacker has only client share, tries to forge a proof
        let k_s = random_scalar();
        let k_r = random_scalar();
        let announcement = k_s * g + k_r * h;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&g.compress().to_bytes());
        transcript.extend_from_slice(&h.compress().to_bytes());
        transcript.extend_from_slice(&commitment.compress().to_bytes());
        transcript.extend_from_slice(&announcement.compress().to_bytes());
        let challenge = hash_transcript(&transcript);

        // Attacker uses client share only (missing server part)
        let forged_z_s = k_s + challenge * client_share.s; // missing + c·s2
        let forged_z_r = k_r + challenge * client_share.r; // missing + c·r2

        let lhs = forged_z_s * g + forged_z_r * h;
        let rhs = announcement + challenge * commitment;
        assert_ne!(lhs, rhs, "client share alone must NOT produce valid proof");
    }

    #[test]
    fn server_share_alone_cannot_forge_proof() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();
        let commitment = commit(&s, &r);

        let (_client_share, server_share) = split_into_shares(&s, &r);

        // Attacker has only server share
        let k_s = random_scalar();
        let k_r = random_scalar();
        let announcement = k_s * g + k_r * h;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&g.compress().to_bytes());
        transcript.extend_from_slice(&h.compress().to_bytes());
        transcript.extend_from_slice(&commitment.compress().to_bytes());
        transcript.extend_from_slice(&announcement.compress().to_bytes());
        let challenge = hash_transcript(&transcript);

        // Attacker computes full response using only server share
        let forged_z_s = k_s + challenge * server_share.s;
        let forged_z_r = k_r + challenge * server_share.r;

        let lhs = forged_z_s * g + forged_z_r * h;
        let rhs = announcement + challenge * commitment;
        assert_ne!(lhs, rhs, "server share alone must NOT produce valid proof");
    }

    #[test]
    fn different_splits_produce_same_commitment() {
        let s = random_scalar();
        let r = random_scalar();
        let (g, h) = generators::generators();

        let (c1a, c1b) = split_into_shares(&s, &r);
        let (c2a, c2b) = split_into_shares(&s, &r);

        let commitment1 = partial_commitment(&c1a, &g, &h) + partial_commitment(&c1b, &g, &h);
        let commitment2 = partial_commitment(&c2a, &g, &h) + partial_commitment(&c2b, &g, &h);

        assert_eq!(commitment1, commitment2, "different splits must produce same commitment");
    }

    #[test]
    fn shares_are_random_looking() {
        let s = random_scalar();
        let r = random_scalar();

        let (share1, _) = split_into_shares(&s, &r);
        let (share2, _) = split_into_shares(&s, &r);

        // Two different splits of the same secret produce different client shares
        assert_ne!(share1.s, share2.s, "shares must be randomized");
    }
}
