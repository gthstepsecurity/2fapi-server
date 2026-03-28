// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RecoveryPhraseGenerator } from "../../../../src/client-registration/domain/service/recovery-phrase-generator.js";
import type { Bip39WordlistProvider } from "../../../../src/client-registration/domain/model/bip39-wordlist.js";
import type { SecureRandomProvider } from "../../../../src/client-registration/domain/port/outgoing/secure-random-provider.js";

function createStubWordlistProvider(): Bip39WordlistProvider {
  // Use a minimal set of known BIP-39 words for testing
  const words: string[] = [];
  for (let i = 0; i < 2048; i++) {
    words.push(`word${i.toString().padStart(4, "0")}`);
  }
  return {
    getWordlist: () => Object.freeze(words),
    getWord: (index: number) => words[index]!,
    indexOf: (word: string) => words.indexOf(word),
  };
}

function createDeterministicRandom(values: number[]): SecureRandomProvider {
  let index = 0;
  return {
    randomIndex(max: number): number {
      const value = values[index % values.length]!;
      index++;
      return value % max;
    },
  };
}

describe("RecoveryPhraseGenerator", () => {
  it("generates a phrase with the requested word count", () => {
    const wordlist = createStubWordlistProvider();
    const random = createDeterministicRandom([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    const generator = new RecoveryPhraseGenerator(wordlist, random);

    const phrase = generator.generate(12);

    expect(phrase.wordCount()).toBe(12);
  });

  it("generates 18 words when requested", () => {
    const wordlist = createStubWordlistProvider();
    const random = createDeterministicRandom(
      Array.from({ length: 18 }, (_, i) => i),
    );
    const generator = new RecoveryPhraseGenerator(wordlist, random);

    const phrase = generator.generate(18);

    expect(phrase.wordCount()).toBe(18);
  });

  it("generates 24 words when requested", () => {
    const wordlist = createStubWordlistProvider();
    const random = createDeterministicRandom(
      Array.from({ length: 24 }, (_, i) => i),
    );
    const generator = new RecoveryPhraseGenerator(wordlist, random);

    const phrase = generator.generate(24);

    expect(phrase.wordCount()).toBe(24);
  });

  it("selects words from the wordlist using the secure random provider", () => {
    const wordlist = createStubWordlistProvider();
    // These indices map to word0005, word0010, word0015, ...
    const indices = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60];
    const random = createDeterministicRandom(indices);
    const generator = new RecoveryPhraseGenerator(wordlist, random);

    const phrase = generator.generate(12);
    const display = phrase.toDisplayString();

    expect(display).toBe(
      "word0005 word0010 word0015 word0020 word0025 word0030 word0035 word0040 word0045 word0050 word0055 word0060",
    );
  });

  it("uses different random values for each word", () => {
    const wordlist = createStubWordlistProvider();
    // All different indices
    const random = createDeterministicRandom([100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200]);
    const generator = new RecoveryPhraseGenerator(wordlist, random);

    const phrase = generator.generate(12);
    const words = phrase.toDisplayString().split(" ");

    // All words should be distinct because all indices are distinct
    const uniqueWords = new Set(words);
    expect(uniqueWords.size).toBe(12);
  });
});
