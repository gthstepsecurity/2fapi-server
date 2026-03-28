// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for cryptographic operations.
 * Implemented by WasmCryptoEngine (browser) or NativeCryptoEngine (Node.js).
 */
export interface CryptoEngine {
  /**
   * Derive a secret and blinding factor from a credential (passphrase or PIN).
   * Uses Argon2id internally.
   */
  deriveCredential(
    credential: string,
    email: string,
    tenantId: string,
  ): Promise<DerivedSecret>;

  /**
   * Compute a Pedersen commitment C = s·G + r·H.
   */
  computeCommitment(secret: Uint8Array, blinding: Uint8Array): Uint8Array;

  /**
   * Generate a Sigma proof of knowledge of (s, r) opening commitment C.
   */
  generateProof(params: ProofParams): Uint8Array;

  /**
   * Derive a vault key from password + pepper using Argon2id + HKDF.
   * Returns 256-bit AES key.
   */
  deriveVaultKey(
    password: string,
    pepper: Uint8Array,
    deviceId: string,
    email: string,
    tenantId: string,
  ): Promise<Uint8Array>;

  /**
   * Encrypt plaintext with AES-256-GCM.
   * Returns { iv, ciphertext, tag }.
   */
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<EncryptedPayload>;

  /**
   * Decrypt ciphertext with AES-256-GCM.
   * Throws on authentication tag mismatch (wrong key or corrupted data).
   */
  decrypt(
    key: Uint8Array,
    encrypted: EncryptedPayload,
  ): Promise<Uint8Array>;

  /**
   * Overwrite a Uint8Array with zeros (best-effort memory zeroization).
   */
  zeroize(buffer: Uint8Array): void;

  /**
   * OPRF: blind the password into a group element + blinding factor.
   */
  oprfBlind(password: string): OprfBlindResult;

  /**
   * OPRF: unblind the server's evaluated point using the blinding factor.
   */
  oprfUnblind(evaluated: Uint8Array, blindingFactor: Uint8Array): Uint8Array;

  /**
   * Derive vault key from OPRF output U via HKDF (no plaintext pepper).
   */
  deriveVaultKeyFromOprf(oprfOutput: Uint8Array, deviceId: string): Promise<Uint8Array>;

  /**
   * Double-lock credential derivation (R14-01 fix):
   * Combines Argon2id(passphrase) with OPRF(enrollment_key, passphrase).
   * Neither the passphrase alone NOR the server alone can derive the secret.
   * Returns (secret, blinding) — same as deriveCredential but OPRF-hardened.
   */
  deriveCredentialWithOprf(
    credential: string,
    email: string,
    tenantId: string,
    oprfOutput: Uint8Array,
  ): Promise<DerivedSecret>;
}

export interface OprfBlindResult {
  readonly blindedPoint: Uint8Array;
  readonly blindingFactor: Uint8Array;
}

export interface DerivedSecret {
  readonly secret: Uint8Array;
  readonly blinding: Uint8Array;
}

export interface ProofParams {
  readonly secret: Uint8Array;
  readonly blinding: Uint8Array;
  readonly commitment: Uint8Array;
  readonly nonce: Uint8Array;
  readonly channelBinding: Uint8Array;
  readonly clientIdentifier: string;
}

export interface EncryptedPayload {
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}
