// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: provides the full BIP-39 English wordlist for the SDK.
 * Lazily loaded — the 2048-word list is only fetched when needed.
 * R13-03 fix: verifies SHA-256 hash of the wordlist content at load time.
 */

/** SHA-256 of the canonical BIP-39 English wordlist (joined by newlines). */
const BIP39_EXPECTED_HASH = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";

export class Bip39WordlistProvider {
  private wordlist: readonly string[] | null = null;

  constructor(
    private readonly loader: () => Promise<readonly string[]>,
    private readonly hashFn?: (data: string) => Promise<string>,
  ) {}

  async getWordlist(): Promise<readonly string[]> {
    if (!this.wordlist) {
      this.wordlist = await this.loader();
      if (this.wordlist.length !== 2048) {
        throw new Error(`BIP-39 wordlist must have 2048 entries, got ${this.wordlist.length}`);
      }
      // R13-03 FIX: verify wordlist integrity via SHA-256 hash
      if (this.hashFn) {
        const content = this.wordlist.join("\n");
        const hash = await this.hashFn(content);
        if (hash !== BIP39_EXPECTED_HASH) {
          this.wordlist = null;
          throw new Error("BIP-39 wordlist integrity check failed — possible supply chain attack");
        }
      }
    }
    return this.wordlist;
  }

  async getWord(index: number): Promise<string | null> {
    const list = await this.getWordlist();
    return (index >= 0 && index < list.length) ? (list[index] ?? null) : null;
  }

  async indexOf(word: string): Promise<number> {
    const list = await this.getWordlist();
    return list.indexOf(word.toLowerCase());
  }

  async chainedHash(indexes: readonly [number, number, number, number], salt: Uint8Array): Promise<Uint8Array> {
    throw new Error("chainedHash requires WASM/NAPI module");
  }
}
