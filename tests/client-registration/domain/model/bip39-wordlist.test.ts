// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  BIP39_WORD_COUNT,
  BIP39_WORDLIST_CHECKSUM,
  type Bip39WordlistProvider,
} from "../../../../src/client-registration/domain/model/bip39-wordlist.js";

describe("BIP39 Wordlist Constants", () => {
  it("defines the standard BIP-39 word count as 2048", () => {
    expect(BIP39_WORD_COUNT).toBe(2048);
  });

  it("defines a SHA-256 checksum string for integrity verification", () => {
    expect(typeof BIP39_WORDLIST_CHECKSUM).toBe("string");
    expect(BIP39_WORDLIST_CHECKSUM.length).toBeGreaterThan(0);
  });

  it("checksum is a valid hex-encoded SHA-256 hash (64 hex chars)", () => {
    expect(BIP39_WORDLIST_CHECKSUM).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("Bip39WordlistProvider interface contract", () => {
  // Verify the interface shape by creating a minimal test implementation
  it("can be implemented with getWordlist, getWord, and indexOf", () => {
    const testProvider: Bip39WordlistProvider = {
      getWordlist(): readonly string[] {
        return ["abandon", "ability"] as const;
      },
      getWord(index: number): string {
        const words = ["abandon", "ability"];
        return words[index] ?? "";
      },
      indexOf(word: string): number {
        const words = ["abandon", "ability"];
        return words.indexOf(word);
      },
    };

    expect(testProvider.getWordlist()).toEqual(["abandon", "ability"]);
    expect(testProvider.getWord(0)).toBe("abandon");
    expect(testProvider.getWord(1)).toBe("ability");
    expect(testProvider.indexOf("abandon")).toBe(0);
    expect(testProvider.indexOf("unknown")).toBe(-1);
  });
});
