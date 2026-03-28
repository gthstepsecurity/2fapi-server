// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../model/result.js";
export interface MaskedSuggestion {
    readonly masked: string;
    readonly length: number;
    readonly firstChar: string;
    readonly index: number;
}
/**
 * Domain service for BIP-39 passphrase validation, autocomplete, and normalization.
 * Pure logic — no infrastructure dependencies.
 */
export declare class PassphraseValidator {
    private readonly wordlist;
    private readonly wordSet;
    constructor(wordlist: readonly string[]);
    /**
     * Validate and normalize a passphrase string into exactly 4 BIP-39 words.
     */
    validate(raw: string): Result<readonly [string, string, string, string], string>;
    /**
     * Suggest BIP-39 words starting with a given prefix.
     * Returns full words for internal logic (validation, selection).
     */
    autocomplete(prefix: string): readonly string[];
    /**
     * Suggest BIP-39 words with partial masking for screen-safe display.
     * Shows first letter + word length only (R13-02 fix).
     *
     * Example: "abandon" → "a______" (7 chars)
     *
     * This prevents screen recording, shoulder-surfing, and accessibility
     * tool leakage from exposing the full passphrase via autocomplete dropdown.
     * The user sees enough to identify their word (first letter + length),
     * but an observer sees ~50 candidates per field instead of 1.
     */
    autocompleteMasked(prefix: string): readonly MaskedSuggestion[];
    /**
     * Resolve a masked suggestion back to the full word.
     * Called ONLY when the user selects a suggestion (not displayed on screen).
     */
    resolveFromIndex(index: number): string | null;
    /**
     * Suggest similar BIP-39 words for a typo (Levenshtein distance <= 2).
     */
    suggestSimilar(word: string): readonly string[];
    /**
     * Split a pasted string into individual words.
     */
    splitPasted(pasted: string): readonly string[];
    private normalize;
}
//# sourceMappingURL=passphrase-validator.d.ts.map
