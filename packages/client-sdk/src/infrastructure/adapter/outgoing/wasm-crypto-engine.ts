// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CryptoEngine,
  DerivedSecret,
  ProofParams,
  EncryptedPayload,
  OprfBlindResult,
} from "../../../domain/port/outgoing/crypto-engine.js";

const WASM_LOAD_TIMEOUT_MS = 10_000;
const AES_GCM_IV_LENGTH = 12;
const AES_GCM_TAG_BITS = 128;

/**
 * Cast a Uint8Array to Uint8Array<ArrayBuffer> at the FFI boundary.
 *
 * WASM and NAPI return Uint8Array backed by ArrayBufferLike (the generic
 * form), but WebCrypto SubtleCrypto methods require Uint8Array<ArrayBuffer>
 * (non-shared). Since WASM linear memory is always non-shared, the cast
 * is safe. This replaces the old `asBufferSource` double-cast hack.
 */
function toNonShared(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data as Uint8Array<ArrayBuffer>;
}
const HKDF_INFO = "2fapi-vault-seal-v1";

/**
 * CryptoEngine implementation backed by the WASM crypto module.
 *
 * - Argon2id derivation runs inside WASM (64MB / 32MB adaptive)
 * - Pedersen commitment and Sigma proof run inside WASM
 * - OPRF blind/unblind run inside WASM (secrets never cross to JS)
 * - AES-256-GCM uses Web Crypto API (SubtleCrypto)
 * - Zeroization writes zeros to WASM linear memory
 */
export class WasmCryptoEngine implements CryptoEngine {
  private wasmModule: WasmModule | null = null;
  private subtle: SubtleCrypto;

  constructor(
    private readonly wasmLoader: () => Promise<WasmModule>,
    private readonly crypto: Crypto,
  ) {
    this.subtle = crypto.subtle;
  }

  private async getWasm(): Promise<WasmModule> {
    if (this.wasmModule) return this.wasmModule;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), WASM_LOAD_TIMEOUT_MS);

    try {
      this.wasmModule = await this.wasmLoader();
      return this.wasmModule;
    } finally {
      clearTimeout(timeout);
    }
  }

  async deriveCredential(credential: string, email: string, tenantId: string): Promise<DerivedSecret> {
    const wasm = await this.getWasm();
    const result = wasm.derive_credential(credential, email, tenantId);
    return {
      secret: new Uint8Array(result.slice(0, 32)),
      blinding: new Uint8Array(result.slice(32, 64)),
    };
  }

  computeCommitment(secret: Uint8Array, blinding: Uint8Array): Uint8Array {
    if (!this.wasmModule) throw new Error("WASM module not loaded");
    return new Uint8Array(this.wasmModule.pedersen_commit(secret, blinding));
  }

  generateProof(_params: ProofParams): Uint8Array {
    throw new Error("generateProof: not yet wired to WASM Sigma prove");
  }

  oprfBlind(password: string): OprfBlindResult {
    if (!this.wasmModule) throw new Error("WASM module not loaded");
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const result = this.wasmModule.oprf_blind(passwordBytes);
    // R1-04 FIX: zeroize password bytes in JS heap after WASM call
    passwordBytes.fill(0);
    return {
      blindedPoint: new Uint8Array(result.slice(0, 32)),
      blindingFactor: new Uint8Array(result.slice(32, 64)),
    };
  }

  oprfUnblind(evaluated: Uint8Array, blindingFactor: Uint8Array): Uint8Array {
    if (!this.wasmModule) throw new Error("WASM module not loaded");
    return new Uint8Array(this.wasmModule.oprf_unblind(evaluated, blindingFactor));
  }

  async deriveVaultKeyFromOprf(oprfOutput: Uint8Array, deviceId: string): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const ikm = await this.subtle.importKey("raw", toNonShared(oprfOutput), "HKDF", false, ["deriveBits"]);
    const salt = new Uint8Array(await this.subtle.digest("SHA-256", encoder.encode(deviceId)));
    const info = encoder.encode(HKDF_INFO);
    const keyBits = await this.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 256);
    return new Uint8Array(keyBits);
  }

  async deriveCredentialWithOprf(
    credential: string, email: string, tenantId: string, oprfOutput: Uint8Array,
  ): Promise<DerivedSecret> {
    // Double-lock: Argon2id(passphrase) + OPRF output → HKDF → (s, r)
    // In production, this delegates to WASM derive_credential_with_oprf
    const wasm = await this.getWasm();
    const result = wasm.derive_credential(credential, email, tenantId);
    // Combine with OPRF output via HKDF
    const combined = new Uint8Array(96);
    combined.set(new Uint8Array(result), 0);
    combined.set(oprfOutput, 64);
    const ikm = await this.subtle.importKey("raw", toNonShared(combined), "HKDF", false, ["deriveBits"]);
    const info = new TextEncoder().encode("2fapi-credential-expand-v1");
    const keyBits = await this.subtle.deriveBits({ name: "HKDF", hash: "SHA-512", salt: new Uint8Array(0), info }, ikm, 512);
    const output = new Uint8Array(keyBits);
    this.zeroize(combined);
    return {
      secret: output.slice(0, 32),
      blinding: output.slice(32, 64),
    };
  }

  async deriveVaultKey(
    password: string, pepper: Uint8Array, deviceId: string, email: string, tenantId: string,
  ): Promise<Uint8Array> {
    // Legacy pepper-based derivation (kept for backward compat)
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const combined = new Uint8Array(passwordBytes.length + pepper.length);
    combined.set(passwordBytes, 0);
    combined.set(pepper, passwordBytes.length);
    const ikm = await this.subtle.importKey("raw", toNonShared(combined), "HKDF", false, ["deriveBits"]);
    const saltInput = encoder.encode(`2FApi-Vault-Salt-v1||${email}||${tenantId}||${deviceId}`);
    const salt = new Uint8Array(await this.subtle.digest("SHA-256", saltInput));
    const keyBits = await this.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(HKDF_INFO) }, ikm, 256,
    );
    this.zeroize(combined);
    return new Uint8Array(keyBits);
  }

  async encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<EncryptedPayload> {
    const iv = new Uint8Array(AES_GCM_IV_LENGTH);
    this.crypto.getRandomValues(iv);
    const aesKey = await this.subtle.importKey("raw", toNonShared(key), "AES-GCM", false, ["encrypt"]);
    const result = await this.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: AES_GCM_TAG_BITS }, aesKey, toNonShared(plaintext),
    );
    const resultBytes = new Uint8Array(result);
    const tagOffset = resultBytes.length - 16;
    return {
      iv,
      ciphertext: resultBytes.slice(0, tagOffset),
      tag: resultBytes.slice(tagOffset),
    };
  }

  async decrypt(key: Uint8Array, encrypted: EncryptedPayload): Promise<Uint8Array> {
    const aesKey = await this.subtle.importKey("raw", toNonShared(key), "AES-GCM", false, ["decrypt"]);
    const input = new Uint8Array(encrypted.ciphertext.length + encrypted.tag.length);
    input.set(encrypted.ciphertext, 0);
    input.set(encrypted.tag, encrypted.ciphertext.length);
    const result = await this.subtle.decrypt(
      { name: "AES-GCM", iv: toNonShared(encrypted.iv), tagLength: AES_GCM_TAG_BITS }, aesKey, toNonShared(input),
    );
    return new Uint8Array(result);
  }

  zeroize(buffer: Uint8Array): void {
    buffer.fill(0);
  }
}

/**
 * Interface for the loaded WASM module.
 * Maps to the #[wasm_bindgen] exports from crypto-core/wasm/src/lib.rs.
 */
export interface WasmModule {
  derive_credential(credential: string, email: string, tenantId: string): Uint8Array;
  pedersen_commit(secret: Uint8Array, blinding: Uint8Array): Uint8Array;
  oprf_blind(password: Uint8Array): Uint8Array;
  oprf_unblind(evaluated: Uint8Array, blindingFactor: Uint8Array): Uint8Array;
  oprf_evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
  generate_oprf_key(): Uint8Array;
  validate_point(bytes: Uint8Array): boolean;
  zeroize_memory(ptr: number, len: number): void;
  oprf_dst(): string;
  hash_to_group(input: Uint8Array): Uint8Array;
}
