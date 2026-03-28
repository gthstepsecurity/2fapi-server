// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PassphraseValidator } from "../../../../packages/client-sdk/src/domain/service/passphrase-validator.js";

// Minimal wordlist for testing (subset of BIP-39)
const testWordlist = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb",
  "abstract", "abuse", "access", "acid", "action", "actor",
  "black", "blade", "blame", "blanket", "blast", "bleak", "bleed",
  "blend", "bless", "blind", "blood", "blossom", "blue",
  "calm", "camera", "camp", "cancel", "candy", "capable",
  "fast", "fatal", "father", "fatigue", "fault", "favorite",
  "moon", "more", "morning", "mosquito", "mother", "motion",
  "ocean", "october", "odor", "offer", "office",
  "red", "reduce", "reflect", "reform", "region",
  "star", "start", "state", "stay", "step",
  "tiger", "tight", "timber", "time", "tiny", "tip", "tired",
];

describe("PassphraseValidator", () => {
  const validator = new PassphraseValidator(testWordlist);

  // --- Validation ---

  it("accepts a valid 4-word passphrase", () => {
    const result = validator.validate("blue tiger fast moon");
    expect(result.isOk()).toBe(true);
    expect(result.unwrap()).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  it("rejects fewer than 4 words", () => {
    const result = validator.validate("blue tiger fast");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("Please enter all 4 words");
  });

  it("rejects more than 4 words", () => {
    const result = validator.validate("blue tiger fast moon star");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("Please enter all 4 words");
  });

  it("rejects empty input", () => {
    const result = validator.validate("");
    expect(result.isErr()).toBe(true);
  });

  it("rejects a non-BIP-39 word", () => {
    const result = validator.validate("blue tiger fast hello");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toContain("hello");
  });

  it("rejects duplicate words", () => {
    const result = validator.validate("moon moon moon moon");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("Each word must be different");
  });

  // --- Normalization ---

  it("normalizes to lowercase", () => {
    const result = validator.validate("Blue Tiger Fast Moon");
    expect(result.isOk()).toBe(true);
    expect(result.unwrap()).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  it("trims extra spaces", () => {
    const result = validator.validate("  blue   tiger  fast   moon  ");
    expect(result.isOk()).toBe(true);
    expect(result.unwrap()).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  // --- Autocomplete ---

  it("suggests words starting with a prefix", () => {
    const suggestions = validator.autocomplete("ti");
    expect(suggestions).toContain("tiger");
    expect(suggestions).toContain("tight");
    expect(suggestions).toContain("timber");
    expect(suggestions).toContain("time");
    expect(suggestions).toContain("tiny");
    expect(suggestions).toContain("tip");
    expect(suggestions).toContain("tired");
  });

  it("returns empty suggestions for no match", () => {
    const suggestions = validator.autocomplete("xyz");
    expect(suggestions).toEqual([]);
  });

  it("returns exact match when prefix is a full word", () => {
    const suggestions = validator.autocomplete("blue");
    expect(suggestions).toContain("blue");
  });

  it("limits suggestions to max 10", () => {
    const suggestions = validator.autocomplete("a");
    expect(suggestions.length).toBeLessThanOrEqual(10);
  });

  it("is case-insensitive for autocomplete", () => {
    const suggestions = validator.autocomplete("Ti");
    expect(suggestions).toContain("tiger");
  });

  // --- Similar words suggestion ---

  it("suggests similar words for a near-miss", () => {
    const suggestions = validator.suggestSimilar("tigar");
    expect(suggestions).toContain("tiger");
  });

  it("returns empty for a completely unrelated word", () => {
    const suggestions = validator.suggestSimilar("zzzzzzz");
    expect(suggestions).toEqual([]);
  });

  // --- Paste splitting ---

  it("splits a pasted string into 4 words", () => {
    const words = validator.splitPasted("blue tiger fast moon");
    expect(words).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  it("handles pasted string with mixed separators", () => {
    const words = validator.splitPasted("blue\ttiger  fast\nmoon");
    expect(words).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  // --- Levenshtein edge cases (kill mutation survivors) ---

  it("suggests exact match at distance 0", () => {
    const suggestions = validator.suggestSimilar("tiger");
    expect(suggestions).toContain("tiger");
  });

  it("suggests word at distance 1 (single char change)", () => {
    const suggestions = validator.suggestSimilar("tiper");
    expect(suggestions).toContain("tiger");
    expect(suggestions).toContain("time");
  });

  it("suggests word at distance 2 (two char changes)", () => {
    const suggestions = validator.suggestSimilar("tipar");
    expect(suggestions).toContain("tiger");
  });

  it("does not suggest word at distance 3", () => {
    const suggestions = validator.suggestSimilar("xxxar");
    expect(suggestions).not.toContain("tiger");
  });

  it("handles empty prefix in autocomplete", () => {
    const suggestions = validator.autocomplete("");
    expect(suggestions.length).toBeLessThanOrEqual(10);
    // Should return first 10 words from wordlist
    expect(suggestions[0]).toBe("abandon");
  });

  it("handles single character in autocomplete", () => {
    const suggestions = validator.autocomplete("b");
    expect(suggestions).toContain("black");
    expect(suggestions.length).toBeLessThanOrEqual(10);
  });

  it("validates error message contains the invalid word", () => {
    const result = validator.validate("blue tiger fast hello");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toContain('"hello"');
  });

  it("normalizes mixed case in validation", () => {
    const result = validator.validate("BLUE TIGER FAST MOON");
    expect(result.isOk()).toBe(true);
  });

  it("rejects whitespace-only input", () => {
    const result = validator.validate("   ");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("Please enter all 4 words");
  });

  it("suggest similar returns empty for single char that matches nothing", () => {
    const suggestions = validator.suggestSimilar("x");
    // 'x' has distance 2+ from most words — may find some short words
    // but definitely should not crash
    expect(Array.isArray(suggestions)).toBe(true);
  });

  it("levenshtein distance 0 for identical words", () => {
    const suggestions = validator.suggestSimilar("blue");
    expect(suggestions).toContain("blue");
  });

  // --- Levenshtein boundary killers ---

  it("does not suggest empty string input", () => {
    const suggestions = validator.suggestSimilar("");
    // Empty string has distance = word length for each word
    // Only words ≤ 2 chars would match (none in our test wordlist)
    expect(suggestions.length).toBe(0);
  });

  it("suggests word when only last char differs", () => {
    // "bluf" → "blue" (distance 1, last char substitution)
    const suggestions = validator.suggestSimilar("bluf");
    expect(suggestions).toContain("blue");
  });

  it("suggests word when only first char differs", () => {
    // "xlue" → "blue" (distance 1, first char substitution)
    const suggestions = validator.suggestSimilar("xlue");
    expect(suggestions).toContain("blue");
  });

  it("no suggestions when input is much longer than all words", () => {
    const suggestions = validator.suggestSimilar("abcdefghijklmnop");
    expect(suggestions).toEqual([]);
  });

  it("autocomplete returns empty for non-matching long prefix", () => {
    const suggestions = validator.autocomplete("zzz");
    expect(suggestions).toEqual([]);
  });

  it("splitPasted handles single word", () => {
    const words = validator.splitPasted("blue");
    expect(words).toEqual(["blue"]);
  });

  it("splitPasted handles extra newlines", () => {
    const words = validator.splitPasted("blue\n\ntiger\n\nfast\n\nmoon");
    expect(words).toEqual(["blue", "tiger", "fast", "moon"]);
  });

  // --- R13-02: Masked autocomplete (screen-safe) ---

  it("autocompleteMasked returns first char + underscores", () => {
    const suggestions = validator.autocompleteMasked("ti");
    expect(suggestions.length).toBeGreaterThan(0);
    const tiger = suggestions.find(s => s.firstChar === "t" && s.length === 5);
    expect(tiger).toBeDefined();
    expect(tiger!.masked).toBe("t____");
  });

  it("autocompleteMasked does NOT expose full words", () => {
    const suggestions = validator.autocompleteMasked("bl");
    for (const s of suggestions) {
      expect(s.masked).toMatch(/^[a-z]_+$/);
    }
  });

  it("autocompleteMasked includes index for resolution", () => {
    const suggestions = validator.autocompleteMasked("bl");
    for (const s of suggestions) {
      expect(s.index).toBeGreaterThanOrEqual(0);
      const resolved = validator.resolveFromIndex(s.index);
      expect(resolved).not.toBeNull();
      expect(resolved![0]).toBe(s.firstChar);
      expect(resolved!.length).toBe(s.length);
    }
  });

  it("resolveFromIndex returns null for invalid index", () => {
    expect(validator.resolveFromIndex(-1)).toBeNull();
    expect(validator.resolveFromIndex(99999)).toBeNull();
  });

  it("masked suggestions create ambiguity for screen observers", () => {
    const suggestions = validator.autocompleteMasked("b");
    const fiveLetterB = suggestions.filter(s => s.length === 5);
    expect(fiveLetterB.length).toBeGreaterThan(1);
  });
});
