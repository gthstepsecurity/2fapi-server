// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Fiat-Shamir transcript construction.
//!
//! Builds the length-prefixed canonical transcript matching the TypeScript
//! server format. This ensures cross-platform compatibility.

/// Canonical domain separation tag for authentication proofs.
pub const PROTOCOL_TAG: &[u8] = b"2FApi-v1.0-Sigma";

/// Builds a length-prefixed Fiat-Shamir transcript.
///
/// Format: LP(tag) || LP(G) || LP(H) || LP(C) || LP(A) || LP(clientId) || LP(nonce) || LP(channelBinding)
/// Where LP(x) = big-endian u32 length prefix + x bytes.
///
/// This MUST match `src/zk-verification/domain/model/transcript.ts` exactly.
pub fn build_transcript(
    tag: &[u8],
    generator_g: &[u8],
    generator_h: &[u8],
    commitment: &[u8],
    announcement: &[u8],
    client_id: &[u8],
    nonce: &[u8],
    channel_binding: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::new();

    write_field(&mut transcript, tag);
    write_field(&mut transcript, generator_g);
    write_field(&mut transcript, generator_h);
    write_field(&mut transcript, commitment);
    write_field(&mut transcript, announcement);
    write_field(&mut transcript, client_id);
    write_field(&mut transcript, nonce);
    write_field(&mut transcript, channel_binding);

    transcript
}

/// Writes a length-prefixed field: 4-byte big-endian u32 length + data bytes.
fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic() {
        let t1 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );
        let t2 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );
        assert_eq!(t1, t2);
    }

    #[test]
    fn different_client_id_produces_different_transcript() {
        let t1 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );
        let t2 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"bob", &[5u8; 16], &[6u8; 32],
        );
        assert_ne!(t1, t2);
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // "ab" + "cd" must differ from "a" + "bcd"
        let t1 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"ab", &[5u8; 16], &[6u8; 32],
        );
        let t2 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"a", &[5u8; 16], &[6u8; 32],
        );
        assert_ne!(t1, t2);
        // t1 is exactly 1 byte longer than t2 (length-prefixed)
        assert_eq!(t1.len(), t2.len() + 1);
    }

    #[test]
    fn announcement_changes_transcript() {
        let t1 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );
        let t2 = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[0xFFu8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );
        assert_ne!(t1, t2);
    }

    #[test]
    fn all_fields_contribute_to_transcript() {
        let base = build_transcript(
            PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32],
            &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32],
        );

        // Changing each field must produce a different transcript
        let variations: Vec<Vec<u8>> = vec![
            build_transcript(b"other-tag", &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32]),
            build_transcript(PROTOCOL_TAG, &[0xFFu8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32]),
            build_transcript(PROTOCOL_TAG, &[1u8; 32], &[0xFFu8; 32], &[3u8; 32], &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32]),
            build_transcript(PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[0xFFu8; 32], &[4u8; 32], b"alice", &[5u8; 16], &[6u8; 32]),
            build_transcript(PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], b"alice", &[0xFFu8; 16], &[6u8; 32]),
            build_transcript(PROTOCOL_TAG, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], b"alice", &[5u8; 16], &[0xFFu8; 32]),
        ];

        for (i, v) in variations.iter().enumerate() {
            assert_ne!(&base, v, "Field {} did not change transcript", i);
        }
    }
}
