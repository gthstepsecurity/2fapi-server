// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Bip39WordlistProvider } from "../model/bip39-wordlist.js";
import type { SecureRandomProvider } from "../port/outgoing/secure-random-provider.js";
import { RecoveryPhrase } from "../model/recovery-phrase.js";

/**
 * Domain service that generates BIP-39 recovery phrases.
 * Selects N random words from the wordlist using a secure random source.
 */
export class RecoveryPhraseGenerator {
  constructor(
    private readonly wordlistProvider: Bip39WordlistProvider,
    private readonly secureRandom: SecureRandomProvider,
  ) {}

  generate(wordCount: 12 | 18 | 24): RecoveryPhrase {
    const wordlist = this.wordlistProvider.getWordlist();
    const words: string[] = [];

    for (let i = 0; i < wordCount; i++) {
      const index = this.secureRandom.randomIndex(wordlist.length);
      words.push(this.wordlistProvider.getWord(index));
    }

    return RecoveryPhrase.create(words);
  }
}
