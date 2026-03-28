// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! BIP-39 English wordlist and utilities for 2FApi.
//!
//! Provides:
//! - The standard 2048-word English BIP-39 wordlist
//! - Index ↔ word conversion
//! - Chained SHA-512 hash for device linking protocol
//!
//! The chained hash is computed as:
//!   h1 = SHA-512(word[i1])
//!   h2 = SHA-512(h1 || word[i2])
//!   h3 = SHA-512(h2 || word[i3])
//!   h4 = SHA-512(h3 || word[i4])
//!
//! The server receives only h4 — never the words or indexes.

use sha2::{Sha512, Digest};

/// The standard BIP-39 English wordlist (2048 words).
/// Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
pub const WORDLIST: &[&str; 2048] = &include!("bip39_wordlist.inc");

/// Validates that an index is in the BIP-39 range (1-2048).
pub fn is_valid_index(index: u16) -> bool {
    index >= 1 && index <= 2048
}

/// Returns the word at the given 1-based index.
pub fn word_at(index: u16) -> Option<&'static str> {
    if index >= 1 && index <= 2048 {
        Some(WORDLIST[(index - 1) as usize])
    } else {
        None
    }
}

/// Returns the 1-based index of a word in the BIP-39 wordlist.
pub fn index_of(word: &str) -> Option<u16> {
    let lower = word.to_ascii_lowercase();
    WORDLIST.iter().position(|&w| w == lower).map(|i| (i + 1) as u16)
}

/// Computes the salted chained SHA-512 hash for 4 BIP-39 indexes.
///
/// The salt prevents rainbow table attacks. The server generates a fresh
/// random salt for each link request and sends it to both devices.
///
/// Hash chain:
///   h1 = SHA-512(salt || word[i1])
///   h2 = SHA-512(h1 || word[i2])
///   h3 = SHA-512(h2 || word[i3])
///   h4 = SHA-512(h3 || word[i4])
///
/// Returns the 64-byte final hash h4, or an error if any index is invalid.
pub fn chained_hash(indexes: &[u16; 4], salt: &[u8]) -> Result<[u8; 64], &'static str> {
    // Validate all indexes
    for &idx in indexes {
        if !is_valid_index(idx) {
            return Err("index must be between 1 and 2048");
        }
    }

    let w1 = WORDLIST[(indexes[0] - 1) as usize];
    let w2 = WORDLIST[(indexes[1] - 1) as usize];
    let w3 = WORDLIST[(indexes[2] - 1) as usize];
    let w4 = WORDLIST[(indexes[3] - 1) as usize];

    // h1 = SHA-512(salt || word1) — salt prevents rainbow table pre-computation
    let mut hasher = Sha512::new();
    hasher.update(salt);
    hasher.update(w1.as_bytes());
    let h1 = hasher.finalize();

    // h2 = SHA-512(h1 || word2)
    let mut hasher = Sha512::new();
    hasher.update(&h1);
    hasher.update(w2.as_bytes());
    let h2 = hasher.finalize();

    // h3 = SHA-512(h2 || word3)
    let mut hasher = Sha512::new();
    hasher.update(&h2);
    hasher.update(w3.as_bytes());
    let h3 = hasher.finalize();

    // h4 = SHA-512(h3 || word4)
    let mut hasher = Sha512::new();
    hasher.update(&h3);
    hasher.update(w4.as_bytes());
    let h4 = hasher.finalize();

    let mut result = [0u8; 64];
    result.copy_from_slice(&h4);
    Ok(result)
}

/// Computes the salted chained SHA-512 hash from 4 words (instead of indexes).
pub fn chained_hash_from_words(words: &[&str; 4], salt: &[u8]) -> Result<[u8; 64], &'static str> {
    let mut indexes = [0u16; 4];
    for (i, word) in words.iter().enumerate() {
        indexes[i] = index_of(word).ok_or("word not in BIP-39 wordlist")?;
    }
    chained_hash(&indexes, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(WORDLIST.len(), 2048);
    }

    #[test]
    fn first_word_is_abandon() {
        assert_eq!(WORDLIST[0], "abandon");
    }

    #[test]
    fn last_word_is_zoo() {
        assert_eq!(WORDLIST[2047], "zoo");
    }

    #[test]
    fn word_at_valid_index() {
        assert_eq!(word_at(1), Some("abandon"));
        assert_eq!(word_at(2048), Some("zoo"));
    }

    #[test]
    fn word_at_invalid_index() {
        assert_eq!(word_at(0), None);
        assert_eq!(word_at(2049), None);
    }

    #[test]
    fn index_of_valid_word() {
        assert_eq!(index_of("abandon"), Some(1));
        assert_eq!(index_of("zoo"), Some(2048));
    }

    #[test]
    fn index_of_case_insensitive() {
        assert_eq!(index_of("Abandon"), Some(1));
        assert_eq!(index_of("ZOO"), Some(2048));
    }

    #[test]
    fn index_of_invalid_word() {
        assert_eq!(index_of("notaword"), None);
    }

    const TEST_SALT: &[u8] = b"test-salt-16bytes";

    #[test]
    fn chained_hash_is_deterministic() {
        let h1 = chained_hash(&[1, 2, 3, 4], TEST_SALT).unwrap();
        let h2 = chained_hash(&[1, 2, 3, 4], TEST_SALT).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn chained_hash_different_order_produces_different_hash() {
        let h1 = chained_hash(&[1, 2, 3, 4], TEST_SALT).unwrap();
        let h2 = chained_hash(&[2, 1, 3, 4], TEST_SALT).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn chained_hash_different_indexes_produce_different_hash() {
        let h1 = chained_hash(&[100, 200, 300, 400], TEST_SALT).unwrap();
        let h2 = chained_hash(&[100, 200, 300, 401], TEST_SALT).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn chained_hash_different_salt_produces_different_hash() {
        let h1 = chained_hash(&[1, 2, 3, 4], b"salt-A").unwrap();
        let h2 = chained_hash(&[1, 2, 3, 4], b"salt-B").unwrap();
        assert_ne!(h1, h2, "different salts must produce different hashes (rainbow table prevention)");
    }

    #[test]
    fn chained_hash_invalid_index_rejected() {
        assert!(chained_hash(&[0, 1, 2, 3], TEST_SALT).is_err());
        assert!(chained_hash(&[1, 2, 3, 2049], TEST_SALT).is_err());
    }

    #[test]
    fn chained_hash_from_words_matches_indexes() {
        let by_idx = chained_hash(&[1, 2, 3, 4], TEST_SALT).unwrap();
        let words = ["abandon", "ability", "able", "about"];
        let by_words = chained_hash_from_words(&words, TEST_SALT).unwrap();
        assert_eq!(by_idx, by_words);
    }

    #[test]
    fn chained_hash_from_words_invalid_word() {
        let words = ["abandon", "notaword", "able", "about"];
        assert!(chained_hash_from_words(&words, TEST_SALT).is_err());
    }

    #[test]
    fn chained_hash_is_64_bytes() {
        let h = chained_hash(&[742, 1891, 203, 1544], TEST_SALT).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn empty_salt_still_works() {
        let h = chained_hash(&[1, 2, 3, 4], &[]).unwrap();
        assert_eq!(h.len(), 64);
    }
}
