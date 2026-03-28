// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CryptoEngine, DerivedSecret, ProofParams, EncryptedPayload } from "../../../domain/port/outgoing/crypto-engine.js";
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
export declare class WebCryptoCryptoEngine implements CryptoEngine {
    private readonly crypto;
    private readonly subtle;
    constructor(crypto: Crypto);
    deriveCredential(_credential: string, _email: string, _tenantId: string): Promise<DerivedSecret>;
    computeCommitment(_secret: Uint8Array, _blinding: Uint8Array): Uint8Array;
    generateProof(_params: ProofParams): Uint8Array;
    deriveVaultKey(password: string, pepper: Uint8Array, deviceId: string, email: string, tenantId: string): Promise<Uint8Array>;
    encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<EncryptedPayload>;
    decrypt(key: Uint8Array, encrypted: EncryptedPayload): Promise<Uint8Array>;
    zeroize(buffer: Uint8Array): void;
    oprfBlind(_password: string): import("../../../domain/port/outgoing/crypto-engine.js").OprfBlindResult;
    oprfUnblind(_evaluated: Uint8Array, _blindingFactor: Uint8Array): Uint8Array;
    deriveVaultKeyFromOprf(oprfOutput: Uint8Array, deviceId: string): Promise<Uint8Array>;
    deriveCredentialWithOprf(_credential: string, _email: string, _tenantId: string, _oprfOutput: Uint8Array): Promise<import("../../../domain/port/outgoing/crypto-engine.js").DerivedSecret>;
}
//# sourceMappingURL=web-crypto-engine.d.ts.map
