// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { createHash } from "node:crypto";
import type { Bip39WordlistProvider } from "../../../domain/model/bip39-wordlist.js";
import { BIP39_ENGLISH_WORDLIST } from "../../../domain/model/bip39-english-wordlist.js";
import { BIP39_WORDLIST_CHECKSUM, BIP39_WORD_COUNT } from "../../../domain/model/bip39-wordlist.js";

/**
 * F07: Verify BIP-39 wordlist integrity at module load.
 * Computes SHA-256 of joined wordlist and compares to known checksum.
 * Throws at startup if the wordlist has been tampered with.
 */
function verifyWordlistIntegrity(): void {
  if (BIP39_ENGLISH_WORDLIST.length !== BIP39_WORD_COUNT) {
    throw new Error(
      `BIP-39 wordlist integrity check failed: expected ${BIP39_WORD_COUNT} words, got ${BIP39_ENGLISH_WORDLIST.length}`,
    );
  }
  const joined = BIP39_ENGLISH_WORDLIST.join("\n");
  const hash = createHash("sha256").update(joined).digest("hex");
  if (hash !== BIP39_WORDLIST_CHECKSUM) {
    throw new Error(
      `BIP-39 wordlist integrity check failed: expected checksum ${BIP39_WORDLIST_CHECKSUM}, got ${hash}`,
    );
  }
}

// Run integrity check at module load time
verifyWordlistIntegrity();

/**
 * BIP-39 wordlist provider backed by the canonical English wordlist.
 * Uses the actual 2048-word BIP-39 list embedded in bip39-english-wordlist.ts.
 * F07: Wordlist integrity is verified at module load via SHA-256 checksum.
 */
export class DefaultBip39WordlistProvider implements Bip39WordlistProvider {
  getWordlist(): readonly string[] {
    return BIP39_ENGLISH_WORDLIST;
  }

  getWord(index: number): string {
    const word = BIP39_ENGLISH_WORDLIST[index];
    if (word === undefined) {
      throw new Error(`BIP-39 wordlist index out of range: ${index}`);
    }
    return word;
  }

  indexOf(word: string): number {
    return BIP39_ENGLISH_WORDLIST.indexOf(word);
  }
}
