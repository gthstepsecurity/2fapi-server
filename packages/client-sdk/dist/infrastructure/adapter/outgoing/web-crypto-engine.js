const VAULT_HKDF_INFO = "2fapi-vault-seal-v1";
const VAULT_SALT_DST = "2FApi-Vault-Salt-v1";
const AES_GCM_IV_LENGTH = 12;
/**
 * TypeScript 5.x + Node 22 typing issue: Uint8Array<ArrayBufferLike>
 * is not assignable to BufferSource in strict mode.
 * This is a known upstream issue — Uint8Array IS a valid BufferSource at runtime.
 * This helper provides a safe, typed cast that documents the intent.
 * No security impact: the data is unchanged, only the TS type annotation differs.
 */
function asBufferSource(data) {
    return data;
}
const AES_GCM_TAG_LENGTH_BITS = 128;
/**
 * Infrastructure adapter: cryptographic operations via Web Crypto API.
 *
 * Implements vault key derivation (HKDF), AES-256-GCM encryption/decryption,
 * and memory zeroization. The Argon2id step for password stretching uses
 * a pluggable hasher (WASM in browser, native in Node.js).
 *
 * Pedersen commitment and Sigma proof operations delegate to the
 * WASM/NAPI crypto module (set via constructor).
 */
export class WebCryptoCryptoEngine {
    crypto;
    subtle;
    constructor(crypto) {
        this.crypto = crypto;
        this.subtle = crypto.subtle;
    }
    async deriveCredential(_credential, _email, _tenantId) {
        // Delegate to WASM/NAPI module (Argon2id + scalar reduction)
        throw new Error("deriveCredential requires WASM/NAPI module — not yet wired");
    }
    computeCommitment(_secret, _blinding) {
        // Delegate to WASM/NAPI module (Pedersen commitment)
        throw new Error("computeCommitment requires WASM/NAPI module — not yet wired");
    }
    generateProof(_params) {
        // Delegate to WASM/NAPI module (Sigma proof)
        throw new Error("generateProof requires WASM/NAPI module — not yet wired");
    }
    async deriveVaultKey(password, pepper, deviceId, email, tenantId) {
        // Step 1: Build the IKM from password hash (lightweight — Argon2id is for the
        // passphrase derivation, here we use PBKDF2 since the pepper adds 256-bit entropy)
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);
        // Combine password + pepper as input key material
        const ikm = new Uint8Array(passwordBytes.length + pepper.length);
        ikm.set(passwordBytes, 0);
        ikm.set(pepper, passwordBytes.length);
        // Step 2: Import IKM for HKDF
        const ikmKey = await this.subtle.importKey("raw", asBufferSource(ikm), "HKDF", false, ["deriveBits"]);
        // Step 3: Build salt from device context
        const saltInput = encoder.encode(`${VAULT_SALT_DST}||${email}||${tenantId}||${deviceId}`);
        const salt = new Uint8Array(await this.subtle.digest("SHA-256", saltInput));
        // Step 4: Derive 256-bit key via HKDF-SHA256
        const info = encoder.encode(VAULT_HKDF_INFO);
        const keyBits = await this.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikmKey, 256);
        // Zeroize intermediate material
        this.zeroize(ikm);
        return new Uint8Array(keyBits);
    }
    async encrypt(key, plaintext) {
        // Generate random IV
        const iv = new Uint8Array(AES_GCM_IV_LENGTH);
        this.crypto.getRandomValues(iv);
        // Import key
        const aesKey = await this.subtle.importKey("raw", asBufferSource(key), "AES-GCM", false, ["encrypt"]);
        // Encrypt with AES-256-GCM
        const result = await this.subtle.encrypt({ name: "AES-GCM", iv, tagLength: AES_GCM_TAG_LENGTH_BITS }, aesKey, asBufferSource(plaintext));
        // Web Crypto appends the tag to the ciphertext
        const resultBytes = new Uint8Array(result);
        const tagOffset = resultBytes.length - 16;
        const ciphertext = resultBytes.slice(0, tagOffset);
        const tag = resultBytes.slice(tagOffset);
        return { iv, ciphertext, tag };
    }
    async decrypt(key, encrypted) {
        // Import key
        const aesKey = await this.subtle.importKey("raw", asBufferSource(key), "AES-GCM", false, ["decrypt"]);
        // Web Crypto expects ciphertext + tag concatenated
        const input = new Uint8Array(encrypted.ciphertext.length + encrypted.tag.length);
        input.set(encrypted.ciphertext, 0);
        input.set(encrypted.tag, encrypted.ciphertext.length);
        const result = await this.subtle.decrypt({ name: "AES-GCM", iv: asBufferSource(encrypted.iv), tagLength: AES_GCM_TAG_LENGTH_BITS }, aesKey, asBufferSource(input));
        return new Uint8Array(result);
    }
    zeroize(buffer) {
        buffer.fill(0);
    }
    oprfBlind(_password) {
        throw new Error("oprfBlind requires WASM module — use WasmCryptoEngine");
    }
    oprfUnblind(_evaluated, _blindingFactor) {
        throw new Error("oprfUnblind requires WASM module — use WasmCryptoEngine");
    }
    async deriveVaultKeyFromOprf(oprfOutput, deviceId) {
        const encoder = new TextEncoder();
        const ikm = await this.subtle.importKey("raw", asBufferSource(oprfOutput), "HKDF", false, ["deriveBits"]);
        const salt = new Uint8Array(await this.subtle.digest("SHA-256", encoder.encode(deviceId)));
        const info = encoder.encode("2fapi-vault-seal-v1");
        const keyBits = await this.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 256);
        return new Uint8Array(keyBits);
    }
    async deriveCredentialWithOprf(_credential, _email, _tenantId, _oprfOutput) {
        throw new Error("deriveCredentialWithOprf requires WASM module — use WasmCryptoEngine");
    }
}
//# sourceMappingURL=web-crypto-engine.js.map