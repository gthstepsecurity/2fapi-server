// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: generates cryptographically random BIP-39 passphrases (R15-01 fix).
 *
 * Server-generated passphrases prevent cross-tenant reuse — the user
 * cannot choose the same passphrase for two different tenants.
 * For state-level deployments: generation MUST be server_mandatory.
 */
export class PassphraseGenerator {
  constructor(
    private readonly wordlist: readonly string[],
    private readonly randomBytes: (n: number) => Uint8Array,
  ) {}

  /**
   * Generate a random passphrase of N BIP-39 words.
   * Each word is selected uniformly at random from the 2048-word list.
   */
  generate(wordCount: 4 | 6 | 8 = 6): GeneratedPassphrase {
    const indexes: number[] = [];
    const words: string[] = [];

    for (let i = 0; i < wordCount; i++) {
      const index = this.randomWordIndex();
      // Ensure no duplicate words
      if (indexes.includes(index)) {
        i--;
        continue;
      }
      indexes.push(index);
      words.push(this.wordlist[index]!);
    }

    const entropy = Math.floor(Math.log2(Math.pow(this.wordlist.length, wordCount)));

    return {
      words: Object.freeze([...words]) as readonly string[],
      passphrase: words.join(" "),
      wordCount,
      entropyBits: entropy,
      strength: entropy >= 60 ? "strong" : entropy >= 44 ? "moderate" : "weak",
    };
  }

  /**
   * Estimate the strength of a user-chosen passphrase (R12-03 fix).
   */
  estimateStrength(words: readonly string[]): PassphraseStrength {
    const uniqueWords = new Set(words);
    const allInWordlist = words.every(w => this.wordlist.includes(w.toLowerCase()));

    if (!allInWordlist) {
      return { entropyBits: 0, strength: "invalid", reason: "Words not in BIP-39 wordlist" };
    }

    if (uniqueWords.size < words.length) {
      return { entropyBits: 0, strength: "weak", reason: "Duplicate words reduce entropy" };
    }

    const entropy = Math.floor(Math.log2(Math.pow(this.wordlist.length, words.length)));

    // Check for sequential/alphabetical patterns
    const sorted = [...words].sort();
    const isAlphabetical = words.every((w, i) => w === sorted[i]);
    if (isAlphabetical && words.length > 2) {
      return { entropyBits: entropy, strength: "weak", reason: "Alphabetical order is predictable" };
    }

    if (entropy >= 60) return { entropyBits: entropy, strength: "strong" };
    if (entropy >= 44) return { entropyBits: entropy, strength: "moderate" };
    return { entropyBits: entropy, strength: "weak", reason: `Only ${entropy} bits of entropy` };
  }

  private randomWordIndex(): number {
    const bytes = this.randomBytes(2);
    // Uniform selection from 0-2047 (11 bits)
    const value = ((bytes[0]! << 8) | bytes[1]!) & 0x7FF;
    return value % this.wordlist.length;
  }
}

export interface GeneratedPassphrase {
  readonly words: readonly string[];
  readonly passphrase: string;
  readonly wordCount: number;
  readonly entropyBits: number;
  readonly strength: "strong" | "moderate" | "weak";
}

export interface PassphraseStrength {
  readonly entropyBits: number;
  readonly strength: "strong" | "moderate" | "weak" | "invalid";
  readonly reason?: string;
}
