/**
 * Domain service: provides the full BIP-39 English wordlist for the SDK.
 * Lazily loaded — the 2048-word list is only fetched when needed.
 * R13-03 fix: verifies SHA-256 hash of the wordlist content at load time.
 */
/** SHA-256 of the canonical BIP-39 English wordlist (joined by newlines). */
const BIP39_EXPECTED_HASH = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";
export class Bip39WordlistProvider {
    loader;
    hashFn;
    wordlist = null;
    constructor(loader, hashFn) {
        this.loader = loader;
        this.hashFn = hashFn;
    }
    async getWordlist() {
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
    async getWord(index) {
        const list = await this.getWordlist();
        return (index >= 0 && index < list.length) ? (list[index] ?? null) : null;
    }
    async indexOf(word) {
        const list = await this.getWordlist();
        return list.indexOf(word.toLowerCase());
    }
    async chainedHash(indexes, salt) {
        throw new Error("chainedHash requires WASM/NAPI module");
    }
}
//# sourceMappingURL=bip39-wordlist-provider.js.map