// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// The BIP-39 English wordlist contains 2048 words.
// In production, load from a verified source (e.g., bip39 npm package).
// For domain modeling, we define the contract and constants.

/** Standard BIP-39 wordlist size */
export const BIP39_WORD_COUNT = 2048;

/**
 * SHA-256 checksum of the canonical BIP-39 English wordlist for integrity verification.
 * Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
 */
export const BIP39_WORDLIST_CHECKSUM =
  "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";

/**
 * Contract for providing BIP-39 wordlist access.
 * Implementations may load the wordlist from different sources
 * (embedded, file, npm package) but must conform to this interface.
 */
export interface Bip39WordlistProvider {
  /** Returns the full wordlist as a readonly array */
  getWordlist(): readonly string[];

  /** Returns the word at the given index (0-2047) */
  getWord(index: number): string;

  /** Returns the index of the word, or -1 if not found */
  indexOf(word: string): number;
}
