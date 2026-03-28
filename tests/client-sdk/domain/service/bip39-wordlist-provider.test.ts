// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Bip39WordlistProvider } from "../../../../packages/client-sdk/src/domain/service/bip39-wordlist-provider.js";

// Generate a 2048-word test list
const testWords = Array.from({ length: 2048 }, (_, i) => `word${String(i).padStart(4, "0")}`);
testWords[0] = "abandon";
testWords[2047] = "zoo";

const loader = async () => testWords;

describe("Bip39WordlistProvider", () => {
  it("loads wordlist lazily on first access", async () => {
    let loadCount = 0;
    const countingLoader = async () => { loadCount++; return testWords; };
    const provider = new Bip39WordlistProvider(countingLoader);

    await provider.getWordlist();
    await provider.getWordlist();
    expect(loadCount).toBe(1);
  });

  it("returns wordlist with 2048 entries", async () => {
    const provider = new Bip39WordlistProvider(loader);
    const list = await provider.getWordlist();
    expect(list.length).toBe(2048);
  });

  it("rejects wordlist with wrong size", async () => {
    const badLoader = async () => ["a", "b", "c"];
    const provider = new Bip39WordlistProvider(badLoader);
    await expect(provider.getWordlist()).rejects.toThrow("2048 entries");
  });

  it("returns word at valid index", async () => {
    const provider = new Bip39WordlistProvider(loader);
    expect(await provider.getWord(0)).toBe("abandon");
    expect(await provider.getWord(2047)).toBe("zoo");
  });

  it("returns null for out-of-range index", async () => {
    const provider = new Bip39WordlistProvider(loader);
    expect(await provider.getWord(-1)).toBeNull();
    expect(await provider.getWord(2048)).toBeNull();
  });

  it("finds index of existing word (case-insensitive)", async () => {
    const provider = new Bip39WordlistProvider(loader);
    expect(await provider.indexOf("abandon")).toBe(0);
    expect(await provider.indexOf("ABANDON")).toBe(0);
  });

  it("returns -1 for non-existent word", async () => {
    const provider = new Bip39WordlistProvider(loader);
    expect(await provider.indexOf("notaword")).toBe(-1);
  });
});
