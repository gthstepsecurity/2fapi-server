// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { BIP39_ENGLISH_WORDLIST } from "../../../../src/client-registration/domain/model/bip39-english-wordlist.js";
import { BIP39_WORDLIST_CHECKSUM } from "../../../../src/client-registration/domain/model/bip39-wordlist.js";

describe("BIP39 English Wordlist", () => {
  it("contains exactly 2048 words", () => {
    expect(BIP39_ENGLISH_WORDLIST.length).toBe(2048);
  });

  it("contains only lowercase alphabetic words", () => {
    for (const word of BIP39_ENGLISH_WORDLIST) {
      expect(word).toMatch(/^[a-z]+$/);
    }
  });

  it("has no duplicate words", () => {
    const uniqueWords = new Set(BIP39_ENGLISH_WORDLIST);
    expect(uniqueWords.size).toBe(2048);
  });

  it("is sorted alphabetically", () => {
    for (let i = 1; i < BIP39_ENGLISH_WORDLIST.length; i++) {
      expect(BIP39_ENGLISH_WORDLIST[i]! > BIP39_ENGLISH_WORDLIST[i - 1]!).toBe(true);
    }
  });

  it("starts with 'abandon' and ends with 'zoo'", () => {
    expect(BIP39_ENGLISH_WORDLIST[0]).toBe("abandon");
    expect(BIP39_ENGLISH_WORDLIST[2047]).toBe("zoo");
  });

  it("is a readonly array (frozen)", () => {
    expect(Object.isFrozen(BIP39_ENGLISH_WORDLIST)).toBe(true);
  });

  it("SHA-256 checksum matches BIP39_WORDLIST_CHECKSUM (F07)", () => {
    const joined = BIP39_ENGLISH_WORDLIST.join("\n");
    const hash = createHash("sha256").update(joined).digest("hex");
    expect(hash).toBe(BIP39_WORDLIST_CHECKSUM);
  });

  it("contains well-known BIP-39 words", () => {
    expect(BIP39_ENGLISH_WORDLIST).toContain("ability");
    expect(BIP39_ENGLISH_WORDLIST).toContain("abstract");
    expect(BIP39_ENGLISH_WORDLIST).toContain("satoshi");
    expect(BIP39_ENGLISH_WORDLIST).toContain("zero");
    expect(BIP39_ENGLISH_WORDLIST).toContain("width");
  });
});
