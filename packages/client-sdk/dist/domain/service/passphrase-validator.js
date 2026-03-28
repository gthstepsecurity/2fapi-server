import { ok, err } from "../model/result.js";
const REQUIRED_WORD_COUNT = 4;
const MAX_SUGGESTIONS = 10;
const MAX_EDIT_DISTANCE = 2;
/**
 * Domain service for BIP-39 passphrase validation, autocomplete, and normalization.
 * Pure logic — no infrastructure dependencies.
 */
export class PassphraseValidator {
    wordlist;
    wordSet;
    constructor(wordlist) {
        this.wordlist = wordlist;
        this.wordSet = new Set(wordlist);
    }
    /**
     * Validate and normalize a passphrase string into exactly 4 BIP-39 words.
     */
    validate(raw) {
        const words = this.normalize(raw);
        if (words.length !== REQUIRED_WORD_COUNT) {
            return err("Please enter all 4 words");
        }
        // Check all words are in wordlist
        for (const word of words) {
            if (!this.wordSet.has(word)) {
                const similar = this.suggestSimilar(word);
                const hint = similar.length > 0 ? ` Did you mean: ${similar.join(", ")}?` : "";
                return err(`"${word}" is not a valid word.${hint}`);
            }
        }
        // Check no duplicates
        const unique = new Set(words);
        if (unique.size !== REQUIRED_WORD_COUNT) {
            return err("Each word must be different");
        }
        return ok(words);
    }
    /**
     * Suggest BIP-39 words starting with a given prefix.
     * Returns full words for internal logic (validation, selection).
     */
    autocomplete(prefix) {
        const lower = prefix.toLowerCase();
        return this.wordlist
            .filter(w => w.startsWith(lower))
            .slice(0, MAX_SUGGESTIONS);
    }
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
    autocompleteMasked(prefix) {
        const words = this.autocomplete(prefix);
        return words.map(w => ({
            masked: w[0] + "_".repeat(w.length - 1),
            length: w.length,
            firstChar: w[0],
            // The full word is NOT included — the caller resolves it
            // by matching (firstChar, length) against the wordlist on selection.
            index: this.wordlist.indexOf(w),
        }));
    }
    /**
     * Resolve a masked suggestion back to the full word.
     * Called ONLY when the user selects a suggestion (not displayed on screen).
     */
    resolveFromIndex(index) {
        return (index >= 0 && index < this.wordlist.length) ? (this.wordlist[index] ?? null) : null;
    }
    /**
     * Suggest similar BIP-39 words for a typo (Levenshtein distance <= 2).
     */
    suggestSimilar(word) {
        const lower = word.toLowerCase();
        return this.wordlist
            .filter(w => levenshtein(w, lower) <= MAX_EDIT_DISTANCE)
            .slice(0, 5);
    }
    /**
     * Split a pasted string into individual words.
     */
    splitPasted(pasted) {
        return this.normalize(pasted);
    }
    normalize(raw) {
        return raw
            .toLowerCase()
            .trim()
            .split(/[\s\t\n]+/)
            .filter(w => w.length > 0);
    }
}
/**
 * Levenshtein edit distance between two strings.
 */
function levenshtein(a, b) {
    const m = a.length;
    const n = b.length;
    if (m === 0)
        return n;
    if (n === 0)
        return m;
    // Single-row optimization
    const row = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
        let prev = i;
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            const current = Math.min(row[j] + 1, // deletion
            prev + 1, // insertion
            row[j - 1] + cost);
            row[j - 1] = prev;
            prev = current;
        }
        row[n] = prev;
    }
    return row[n];
}
//# sourceMappingURL=passphrase-validator.js.map