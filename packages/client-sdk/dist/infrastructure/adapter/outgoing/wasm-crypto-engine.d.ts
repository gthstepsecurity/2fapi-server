// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CryptoEngine, DerivedSecret, ProofParams, EncryptedPayload, OprfBlindResult } from "../../../domain/port/outgoing/crypto-engine.js";
/**
 * CryptoEngine implementation backed by the WASM crypto module.
 *
 * - Argon2id derivation runs inside WASM (64MB / 32MB adaptive)
 * - Pedersen commitment and Sigma proof run inside WASM
 * - OPRF blind/unblind run inside WASM (secrets never cross to JS)
 * - AES-256-GCM uses Web Crypto API (SubtleCrypto)
 * - Zeroization writes zeros to WASM linear memory
 */
export declare class WasmCryptoEngine implements CryptoEngine {
    private readonly wasmLoader;
    private readonly crypto;
    private wasmModule;
    private subtle;
    constructor(wasmLoader: () => Promise<WasmModule>, crypto: Crypto);
    private getWasm;
    deriveCredential(credential: string, email: string, tenantId: string): Promise<DerivedSecret>;
    computeCommitment(secret: Uint8Array, blinding: Uint8Array): Uint8Array;
    generateProof(_params: ProofParams): Uint8Array;
    oprfBlind(password: string): OprfBlindResult;
    oprfUnblind(evaluated: Uint8Array, blindingFactor: Uint8Array): Uint8Array;
    deriveVaultKeyFromOprf(oprfOutput: Uint8Array, deviceId: string): Promise<Uint8Array>;
    deriveCredentialWithOprf(credential: string, email: string, tenantId: string, oprfOutput: Uint8Array): Promise<DerivedSecret>;
    deriveVaultKey(password: string, pepper: Uint8Array, deviceId: string, email: string, tenantId: string): Promise<Uint8Array>;
    encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<EncryptedPayload>;
    decrypt(key: Uint8Array, encrypted: EncryptedPayload): Promise<Uint8Array>;
    zeroize(buffer: Uint8Array): void;
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
//# sourceMappingURL=wasm-crypto-engine.d.ts.map
