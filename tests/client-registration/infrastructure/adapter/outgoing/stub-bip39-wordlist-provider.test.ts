// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { StubBip39WordlistProvider } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/stub-bip39-wordlist-provider.js";
import { BIP39_WORD_COUNT } from "../../../../../src/client-registration/domain/model/bip39-wordlist.js";

describe("StubBip39WordlistProvider", () => {
  it("provides 2048 words", () => {
    const provider = new StubBip39WordlistProvider();

    const wordlist = provider.getWordlist();

    expect(wordlist.length).toBe(BIP39_WORD_COUNT);
  });

  it("getWord returns the correct word at index 0", () => {
    const provider = new StubBip39WordlistProvider();

    expect(provider.getWord(0)).toBe("abandon");
  });

  it("getWord returns the correct word at index 2047", () => {
    const provider = new StubBip39WordlistProvider();

    expect(provider.getWord(2047)).toBe("zoo");
  });

  it("indexOf returns correct index for known word", () => {
    const provider = new StubBip39WordlistProvider();

    expect(provider.indexOf("abandon")).toBe(0);
    expect(provider.indexOf("zoo")).toBe(2047);
  });

  it("indexOf returns -1 for unknown word", () => {
    const provider = new StubBip39WordlistProvider();

    expect(provider.indexOf("notaword")).toBe(-1);
  });

  it("wordlist is frozen (immutable)", () => {
    const provider = new StubBip39WordlistProvider();

    const wordlist = provider.getWordlist();

    expect(Object.isFrozen(wordlist)).toBe(true);
  });

  it("all words are lowercase alphabetic strings", () => {
    const provider = new StubBip39WordlistProvider();
    const wordlist = provider.getWordlist();

    for (const word of wordlist) {
      expect(word).toMatch(/^[a-z]+$/);
    }
  });
});
