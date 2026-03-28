// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: generates cryptographically random BIP-39 passphrases (R15-01 fix).
 *
 * Server-generated passphrases prevent cross-tenant reuse — the user
 * cannot choose the same passphrase for two different tenants.
 * For state-level deployments: generation MUST be server_mandatory.
 */
export declare class PassphraseGenerator {
    private readonly wordlist;
    private readonly randomBytes;
    constructor(wordlist: readonly string[], randomBytes: (n: number) => Uint8Array);
    /**
     * Generate a random passphrase of N BIP-39 words.
     * Each word is selected uniformly at random from the 2048-word list.
     */
    generate(wordCount?: 4 | 6 | 8): GeneratedPassphrase;
    /**
     * Estimate the strength of a user-chosen passphrase (R12-03 fix).
     */
    estimateStrength(words: readonly string[]): PassphraseStrength;
    private randomWordIndex;
}
export interface GeneratedPassphrase {
    readonly words: readonly string[];
    readonly passphrase: string;
    readonly wordCount: number;
    readonly entropyBits: number;
    readonly strength: "strong" | "moderate" | "weak";
}
export interface PassphraseStrength {
    readonly entropyBits: number;
    readonly strength: "strong" | "moderate" | "weak" | "invalid";
    readonly reason?: string;
}
//# sourceMappingURL=passphrase-generator.d.ts.map
