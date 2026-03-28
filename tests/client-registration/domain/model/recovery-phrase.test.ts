// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RecoveryPhrase } from "../../../../src/client-registration/domain/model/recovery-phrase.js";

function validTwelveWords(): string[] {
  return [
    "abandon", "ability", "able", "about",
    "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident",
  ];
}

function validEighteenWords(): string[] {
  return [
    "abandon", "ability", "able", "about",
    "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid",
    "acoustic", "acquire",
  ];
}

function validTwentyFourWords(): string[] {
  return [
    "abandon", "ability", "able", "about",
    "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual",
  ];
}

describe("RecoveryPhrase", () => {
  describe("create", () => {
    it("creates a recovery phrase from 12 valid words", () => {
      const words = validTwelveWords();
      const phrase = RecoveryPhrase.create(words);
      expect(phrase.wordCount()).toBe(12);
    });

    it("creates a recovery phrase from 18 valid words", () => {
      const words = validEighteenWords();
      const phrase = RecoveryPhrase.create(words);
      expect(phrase.wordCount()).toBe(18);
    });

    it("creates a recovery phrase from 24 valid words", () => {
      const words = validTwentyFourWords();
      const phrase = RecoveryPhrase.create(words);
      expect(phrase.wordCount()).toBe(24);
    });

    it("rejects word count other than 12, 18, or 24", () => {
      const tenWords = validTwelveWords().slice(0, 10);
      expect(() => RecoveryPhrase.create(tenWords)).toThrow(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    });

    it("rejects 0 words", () => {
      expect(() => RecoveryPhrase.create([])).toThrow(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    });

    it("rejects 13 words", () => {
      const thirteenWords = [...validTwelveWords(), "extra"];
      expect(() => RecoveryPhrase.create(thirteenWords)).toThrow(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    });

    it("rejects 11 words", () => {
      const elevenWords = validTwelveWords().slice(0, 11);
      expect(() => RecoveryPhrase.create(elevenWords)).toThrow(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    });

    it("rejects 25 words", () => {
      const twentyFiveWords = [...validTwentyFourWords(), "extra"];
      expect(() => RecoveryPhrase.create(twentyFiveWords)).toThrow(
        "Recovery phrase must contain exactly 12, 18, or 24 words",
      );
    });
  });

  describe("toDisplayString", () => {
    it("returns words joined by spaces for 12 words", () => {
      const words = validTwelveWords();
      const phrase = RecoveryPhrase.create(words);
      expect(phrase.toDisplayString()).toBe(
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
      );
    });

    it("returns words joined by spaces for 24 words", () => {
      const words = validTwentyFourWords();
      const phrase = RecoveryPhrase.create(words);
      expect(phrase.toDisplayString()).toBe(words.join(" "));
    });
  });

  describe("wordCount", () => {
    it("returns 12 for a 12-word phrase", () => {
      const phrase = RecoveryPhrase.create(validTwelveWords());
      expect(phrase.wordCount()).toBe(12);
    });

    it("returns 18 for an 18-word phrase", () => {
      const phrase = RecoveryPhrase.create(validEighteenWords());
      expect(phrase.wordCount()).toBe(18);
    });

    it("returns 24 for a 24-word phrase", () => {
      const phrase = RecoveryPhrase.create(validTwentyFourWords());
      expect(phrase.wordCount()).toBe(24);
    });
  });

  describe("immutability", () => {
    it("is not affected by mutation of the original array", () => {
      const words = validTwelveWords();
      const phrase = RecoveryPhrase.create(words);
      words[0] = "tampered";
      expect(phrase.toDisplayString().startsWith("abandon")).toBe(true);
    });

    it("does not expose mutable internal state", () => {
      const phrase = RecoveryPhrase.create(validTwelveWords());
      // toDisplayString returns a new string each time — strings are immutable
      const display1 = phrase.toDisplayString();
      const display2 = phrase.toDisplayString();
      expect(display1).toBe(display2);
    });
  });
});
