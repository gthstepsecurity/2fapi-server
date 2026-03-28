// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * PKCS#11 session abstraction (driven port).
 *
 * Defines the minimal subset of PKCS#11 operations required by 2FApi.
 * Production implementations delegate to a PKCS#11 library (pkcs11js, graphene-pk11).
 * Test implementations use in-memory stubs.
 *
 * Key constraint: Ristretto255 is NOT a standard PKCS#11 mechanism.
 * OPRF keys are stored as HSM-wrapped opaque data objects (CKO_DATA),
 * unwrapped into process-protected memory for constant-time EC math,
 * then zeroized. EdDSA signing (CKM_EDDSA) is performed entirely
 * inside the HSM — the signing key never leaves.
 *
 * HSM compatibility: YubiHSM 2, AWS CloudHSM, Thales Luna, SoftHSM2 (dev).
 */

/** PKCS#11 key handle — opaque reference to a key inside the HSM. */
export type KeyHandle = bigint;

/** Key attributes for generation or import. */
export interface KeyAttributes {
  /** CKA_LABEL — human-readable label for key lookup. */
  readonly label: string;
  /** CKA_EXTRACTABLE — if false, key material cannot leave the HSM. */
  readonly extractable: boolean;
  /** CKA_TOKEN — if true, key persists across sessions. */
  readonly persistent: boolean;
}

/** Wrapping parameters for key export/import with HSM master key. */
export interface WrapParams {
  /** AES-256-GCM wrapping key handle. */
  readonly wrappingKeyHandle: KeyHandle;
  /** Random IV for AES-GCM (12 bytes). */
  readonly iv: Uint8Array;
}

/**
 * Minimal PKCS#11 session interface for 2FApi HSM operations.
 *
 * Implementations:
 * - Pkcs11RealSession    — production (delegates to pkcs11js or graphene-pk11)
 * - Pkcs11StubSession    — test (in-memory key store, software crypto)
 */
export interface Pkcs11Session {
  // --- EdDSA operations (CKM_EDDSA) ---

  /** Generate an Ed25519 key pair inside the HSM. Returns handle to private key. */
  generateEd25519KeyPair(attrs: KeyAttributes): Promise<{
    privateKeyHandle: KeyHandle;
    publicKey: Uint8Array; // 32-byte Ed25519 public key (CKA_EC_POINT)
  }>;

  /** Import an existing Ed25519 private key into the HSM. */
  importEd25519PrivateKey(
    privateKey: Uint8Array,
    attrs: KeyAttributes,
  ): Promise<KeyHandle>;

  /** Sign payload using Ed25519 (CKM_EDDSA). Key never leaves HSM. */
  signEd25519(keyHandle: KeyHandle, payload: Uint8Array): Promise<Uint8Array>;

  /** Find a key by label. Returns null if not found. */
  findKeyByLabel(label: string): Promise<KeyHandle | null>;

  // --- Opaque data operations (for OPRF keys) ---

  /**
   * Store opaque secret data in the HSM, encrypted by the HSM's master key.
   * Used for Ristretto255 OPRF keys which are not standard PKCS#11 key types.
   *
   * The data is stored as CKO_DATA with CKA_SENSITIVE=true, CKA_EXTRACTABLE
   * controlled by the attrs parameter.
   */
  storeOpaqueSecret(data: Uint8Array, attrs: KeyAttributes): Promise<KeyHandle>;

  /**
   * Retrieve opaque secret data from the HSM.
   *
   * Returns the raw bytes. Caller MUST zeroize after use.
   * Only possible if CKA_EXTRACTABLE was set to true at storage time.
   *
   * For non-extractable keys, use unwrapToBuffer instead.
   */
  retrieveOpaqueSecret(handle: KeyHandle): Promise<Uint8Array>;

  /**
   * Delete a key or data object from the HSM.
   * This is a DESTRUCTIVE operation — the key is permanently destroyed.
   */
  destroyObject(handle: KeyHandle): Promise<void>;

  /** Close the PKCS#11 session. Must be called on shutdown. */
  close(): Promise<void>;
}
