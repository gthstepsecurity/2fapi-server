// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  Pkcs11Session,
  KeyHandle,
} from "./pkcs11-session.js";

/**
 * HSM-backed OPRF key vault.
 *
 * Stores Ristretto255 OPRF scalar keys as HSM-encrypted opaque data objects.
 * Unwraps them into process memory ONLY for the constant-time scalar
 * multiplication, then zeroizes immediately.
 *
 * Architecture:
 *
 *   ┌───────────────────────────────────────────────┐
 *   │  HSM (FIPS 140-3 Level 3+)                    │
 *   │  ┌─────────────────────────────────────────┐  │
 *   │  │  OPRF key (32 bytes, AES-256 encrypted) │  │
 *   │  └─────────────────────────────────────────┘  │
 *   └────────────────────┬──────────────────────────┘
 *                        │ retrieveOpaqueSecret()
 *                        ▼
 *   ┌───────────────────────────────────────────────┐
 *   │  Process memory (mlock'd, 32 bytes)           │
 *   │  ┌─────────────────────────────────────────┐  │
 *   │  │  k (scalar)  × B (blinded point)        │  │
 *   │  │  → E = k·B (constant-time, dudect ✓)   │  │
 *   │  └─────────────────────────────────────────┘  │
 *   │  → zeroize(k) immediately after               │
 *   └───────────────────────────────────────────────┘
 *
 * Why not pure HSM EC math:
 *   PKCS#11 does not support Ristretto255 as a native curve.
 *   The HSM protects the key AT REST and during transit.
 *   The scalar multiplication is done in software (constant-time,
 *   verified by dudect — see DUDECT-REPORT.md).
 *
 * The key is extractable (CKA_EXTRACTABLE=true) because the HSM
 * cannot perform Ristretto operations internally. The extraction
 * window is minimized to the duration of the OPRF evaluation
 * (~0.1ms), and the key is zeroized immediately after.
 *
 * For HSMs that support custom EC curves (e.g., Thales Luna with
 * custom firmware), a fully non-extractable implementation is
 * possible by overriding the evaluate() method.
 */
export class HsmOprfKeyVault {
  constructor(
    private readonly session: Pkcs11Session,
    private readonly evaluateFn: (
      blindedPoint: Uint8Array,
      oprfKey: Uint8Array,
    ) => Uint8Array,
    private readonly zeroizeFn: (buf: Uint8Array) => void,
  ) {}

  /**
   * Generate a new OPRF key and store it in the HSM.
   * Returns the HSM key label (not the raw key).
   */
  async generateKey(keyLabel: string): Promise<void> {
    // Generate 32 bytes of cryptographically secure randomness
    const keyBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(keyBytes);

    try {
      await this.session.storeOpaqueSecret(keyBytes, {
        label: keyLabel,
        extractable: true, // Required: HSM cannot do Ristretto math
        persistent: true,
      });
    } finally {
      // Zeroize the plaintext key immediately
      this.zeroizeFn(keyBytes);
    }
  }

  /**
   * Evaluate OPRF: E = k·B where k is the HSM-protected OPRF key.
   *
   * 1. Unwrap key from HSM into process memory
   * 2. Perform constant-time Ristretto scalar multiplication
   * 3. Zeroize key from memory
   *
   * Total key exposure window: ~0.1ms (scalar multiplication time).
   */
  async evaluate(
    keyLabel: string,
    blindedPoint: Uint8Array,
  ): Promise<Uint8Array> {
    const handle = await this.session.findKeyByLabel(keyLabel);
    if (handle === null) {
      throw new Error(
        `OPRF key not found in HSM: "${keyLabel}". ` +
        "Run key ceremony to generate the OPRF key.",
      );
    }

    // Extract key from HSM (minimized exposure window)
    const oprfKey = await this.session.retrieveOpaqueSecret(handle);

    try {
      // Constant-time scalar multiplication (dudect verified)
      return this.evaluateFn(blindedPoint, oprfKey);
    } finally {
      // CRITICAL: zeroize key from process memory immediately
      this.zeroizeFn(oprfKey);
    }
  }

  /**
   * Check if an OPRF key exists in the HSM.
   */
  async hasKey(keyLabel: string): Promise<boolean> {
    const handle = await this.session.findKeyByLabel(keyLabel);
    return handle !== null;
  }

  /**
   * Destroy an OPRF key in the HSM.
   * This is PERMANENT — the key cannot be recovered.
   */
  async destroyKey(keyLabel: string): Promise<void> {
    const handle = await this.session.findKeyByLabel(keyLabel);
    if (handle !== null) {
      await this.session.destroyObject(handle);
    }
  }

  /**
   * Rotate an OPRF key: generate new, return old handle for grace period.
   *
   * During rotation:
   * 1. New key is generated with label "<keyLabel>-next"
   * 2. Caller verifies the new key works (re-derive commitments)
   * 3. Caller renames labels and destroys old key
   */
  async rotateKey(keyLabel: string): Promise<void> {
    const nextLabel = `${keyLabel}-next`;
    await this.generateKey(nextLabel);
  }
}
