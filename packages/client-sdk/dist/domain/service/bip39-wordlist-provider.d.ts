// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: provides the full BIP-39 English wordlist for the SDK.
 * Lazily loaded — the 2048-word list is only fetched when needed.
 * R13-03 fix: verifies SHA-256 hash of the wordlist content at load time.
 */
export declare class Bip39WordlistProvider {
    private readonly loader;
    private readonly hashFn?;
    private wordlist;
    constructor(loader: () => Promise<readonly string[]>, hashFn?: ((data: string) => Promise<string>) | undefined);
    getWordlist(): Promise<readonly string[]>;
    getWord(index: number): Promise<string | null>;
    indexOf(word: string): Promise<number>;
    chainedHash(indexes: readonly [number, number, number, number], salt: Uint8Array): Promise<Uint8Array>;
}
//# sourceMappingURL=bip39-wordlist-provider.d.ts.map
