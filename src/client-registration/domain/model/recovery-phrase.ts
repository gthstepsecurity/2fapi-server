// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const VALID_WORD_COUNTS = [12, 18, 24] as const;
type ValidWordCount = (typeof VALID_WORD_COUNTS)[number];

/**
 * Value Object representing a BIP-39 recovery phrase.
 * Immutable — wraps a readonly array of 12, 18, or 24 words.
 */
export class RecoveryPhrase {
  private readonly words: readonly string[];

  private constructor(words: readonly string[]) {
    this.words = words;
  }

  /**
   * Creates a RecoveryPhrase from an array of words.
   * @throws if word count is not 12, 18, or 24
   */
  static create(words: string[]): RecoveryPhrase {
    if (!VALID_WORD_COUNTS.includes(words.length as ValidWordCount)) {
      throw new Error(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    }
    // Defensive copy to ensure immutability
    return new RecoveryPhrase(Object.freeze([...words]));
  }

  /** Returns the words joined by spaces for display */
  toDisplayString(): string {
    return this.words.join(" ");
  }

  /** Returns the number of words (12, 18, or 24) */
  wordCount(): ValidWordCount {
    return this.words.length as ValidWordCount;
  }
}
