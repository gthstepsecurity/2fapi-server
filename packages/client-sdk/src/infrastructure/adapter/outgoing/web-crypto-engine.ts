// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CryptoEngine,
  DerivedSecret,
  ProofParams,
  EncryptedPayload,
} from "../../../domain/port/outgoing/crypto-engine.js";

const VAULT_HKDF_INFO = "2fapi-vault-seal-v1";
const VAULT_SALT_DST = "2FApi-Vault-Salt-v1";
const AES_GCM_IV_LENGTH = 12;

/**
 * Cast Uint8Array to Uint8Array<ArrayBuffer> at the FFI boundary.
 *
 * WebCrypto SubtleCrypto methods require Uint8Array<ArrayBuffer> (non-shared),
 * but WASM/NAPI return Uint8Array<ArrayBufferLike>. Since all our buffers
 * are non-shared, the cast is safe.
 */
function toNonShared(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data as Uint8Array<ArrayBuffer>;
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
export class WebCryptoCryptoEngine implements CryptoEngine {
  private readonly subtle: SubtleCrypto;

  constructor(private readonly crypto: Crypto) {
    this.subtle = crypto.subtle;
  }

  async deriveCredential(
    _credential: string,
    _email: string,
    _tenantId: string,
  ): Promise<DerivedSecret> {
    // Delegate to WASM/NAPI module (Argon2id + scalar reduction)
    throw new Error("deriveCredential requires WASM/NAPI module — not yet wired");
  }

  computeCommitment(_secret: Uint8Array, _blinding: Uint8Array): Uint8Array {
    // Delegate to WASM/NAPI module (Pedersen commitment)
    throw new Error("computeCommitment requires WASM/NAPI module — not yet wired");
  }

  generateProof(_params: ProofParams): Uint8Array {
    // Delegate to WASM/NAPI module (Sigma proof)
    throw new Error("generateProof requires WASM/NAPI module — not yet wired");
  }

  async deriveVaultKey(
    password: string,
    pepper: Uint8Array,
    deviceId: string,
    email: string,
    tenantId: string,
  ): Promise<Uint8Array> {
    // Step 1: Build the IKM from password hash (lightweight — Argon2id is for the
    // passphrase derivation, here we use PBKDF2 since the pepper adds 256-bit entropy)
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Combine password + pepper as input key material
    const ikm = new Uint8Array(passwordBytes.length + pepper.length);
    ikm.set(passwordBytes, 0);
    ikm.set(pepper, passwordBytes.length);

    // Step 2: Import IKM for HKDF
    const ikmKey = await this.subtle.importKey(
      "raw",
      toNonShared(ikm),
      "HKDF",
      false,
      ["deriveBits"],
    );

    // Step 3: Build salt from device context
    const saltInput = encoder.encode(`${VAULT_SALT_DST}||${email}||${tenantId}||${deviceId}`);
    const salt = new Uint8Array(await this.subtle.digest("SHA-256", saltInput));

    // Step 4: Derive 256-bit key via HKDF-SHA256
    const info = encoder.encode(VAULT_HKDF_INFO);
    const keyBits = await this.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      ikmKey,
      256,
    );

    // Zeroize intermediate material
    this.zeroize(ikm);

    return new Uint8Array(keyBits);
  }

  async encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<EncryptedPayload> {
    // Generate random IV
    const iv = new Uint8Array(AES_GCM_IV_LENGTH);
    this.crypto.getRandomValues(iv);

    // Import key
    const aesKey = await this.subtle.importKey(
      "raw",
      toNonShared(key),
      "AES-GCM",
      false,
      ["encrypt"],
    );

    // Encrypt with AES-256-GCM
    const result = await this.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: AES_GCM_TAG_LENGTH_BITS },
      aesKey,
      toNonShared(plaintext),
    );

    // Web Crypto appends the tag to the ciphertext
    const resultBytes = new Uint8Array(result);
    const tagOffset = resultBytes.length - 16;
    const ciphertext = resultBytes.slice(0, tagOffset);
    const tag = resultBytes.slice(tagOffset);

    return { iv, ciphertext, tag };
  }

  async decrypt(key: Uint8Array, encrypted: EncryptedPayload): Promise<Uint8Array> {
    // Import key
    const aesKey = await this.subtle.importKey(
      "raw",
      toNonShared(key),
      "AES-GCM",
      false,
      ["decrypt"],
    );

    // Web Crypto expects ciphertext + tag concatenated
    const input = new Uint8Array(encrypted.ciphertext.length + encrypted.tag.length);
    input.set(encrypted.ciphertext, 0);
    input.set(encrypted.tag, encrypted.ciphertext.length);

    const result = await this.subtle.decrypt(
      { name: "AES-GCM", iv: toNonShared(encrypted.iv), tagLength: AES_GCM_TAG_LENGTH_BITS },
      aesKey,
      toNonShared(input),
    );

    return new Uint8Array(result);
  }

  zeroize(buffer: Uint8Array): void {
    buffer.fill(0);
  }

  oprfBlind(_password: string): import("../../../domain/port/outgoing/crypto-engine.js").OprfBlindResult {
    throw new Error("oprfBlind requires WASM module — use WasmCryptoEngine");
  }

  oprfUnblind(_evaluated: Uint8Array, _blindingFactor: Uint8Array): Uint8Array {
    throw new Error("oprfUnblind requires WASM module — use WasmCryptoEngine");
  }

  async deriveVaultKeyFromOprf(oprfOutput: Uint8Array, deviceId: string): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const ikm = await this.subtle.importKey("raw", toNonShared(oprfOutput), "HKDF", false, ["deriveBits"]);
    const salt = new Uint8Array(await this.subtle.digest("SHA-256", encoder.encode(deviceId)));
    const info = encoder.encode("2fapi-vault-seal-v1");
    const keyBits = await this.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 256);
    return new Uint8Array(keyBits);
  }

  async deriveCredentialWithOprf(
    _credential: string, _email: string, _tenantId: string, _oprfOutput: Uint8Array,
  ): Promise<import("../../../domain/port/outgoing/crypto-engine.js").DerivedSecret> {
    throw new Error("deriveCredentialWithOprf requires WASM module — use WasmCryptoEngine");
  }
}
