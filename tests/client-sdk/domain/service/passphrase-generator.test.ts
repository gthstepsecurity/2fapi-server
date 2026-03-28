// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PassphraseGenerator } from "../../../../packages/client-sdk/src/domain/service/passphrase-generator.js";

const testWords = Array.from({ length: 2048 }, (_, i) => `word${String(i).padStart(4, "0")}`);
let callCount = 0;
const mockRandom = (n: number) => {
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    bytes[i] = ((callCount++ * 137 + 43) % 256);
  }
  return bytes;
};

describe("PassphraseGenerator", () => {
  it("generates a 6-word passphrase by default", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate();
    expect(result.wordCount).toBe(6);
    expect(result.words.length).toBe(6);
    expect(result.passphrase.split(" ").length).toBe(6);
  });

  it("generates a 4-word passphrase when requested", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(4);
    expect(result.wordCount).toBe(4);
    expect(result.words.length).toBe(4);
  });

  it("generates an 8-word passphrase when requested", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(8);
    expect(result.wordCount).toBe(8);
    expect(result.words.length).toBe(8);
  });

  it("ensures no duplicate words", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(6);
    const unique = new Set(result.words);
    expect(unique.size).toBe(6);
  });

  it("all words are from the wordlist", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(6);
    for (const word of result.words) {
      expect(testWords).toContain(word);
    }
  });

  it("calculates entropy correctly for 4 words", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(4);
    expect(result.entropyBits).toBe(44); // log2(2048^4) = 44
  });

  it("calculates entropy correctly for 6 words", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.generate(6);
    expect(result.entropyBits).toBe(66); // log2(2048^6) = 66
  });

  it("rates 6-word passphrase as strong", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    expect(gen.generate(6).strength).toBe("strong");
  });

  it("rates 4-word passphrase as moderate", () => {
    callCount = 0;
    const gen = new PassphraseGenerator(testWords, mockRandom);
    expect(gen.generate(4).strength).toBe("moderate");
  });

  // --- Strength estimator ---

  it("estimates 6 non-sequential known words as strong", () => {
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.estimateStrength(["word0500", "word0100", "word1800", "word0042", "word0999", "word1500"]);
    expect(result.strength).toBe("strong");
    expect(result.entropyBits).toBe(66);
  });

  it("detects duplicate words as weak", () => {
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.estimateStrength(["word0001", "word0001", "word0003", "word0004"]);
    expect(result.strength).toBe("weak");
    expect(result.reason).toContain("Duplicate");
  });

  it("detects non-BIP39 words as invalid", () => {
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const result = gen.estimateStrength(["hello", "world", "foo", "bar"]);
    expect(result.strength).toBe("invalid");
  });

  it("detects alphabetical order as weak", () => {
    const gen = new PassphraseGenerator(testWords, mockRandom);
    const words = ["word0001", "word0002", "word0003", "word0004"];
    const result = gen.estimateStrength(words);
    expect(result.strength).toBe("weak");
    expect(result.reason).toContain("Alphabetical");
  });
});
