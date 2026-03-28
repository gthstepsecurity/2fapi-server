// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenSigner } from "../../../domain/port/outgoing/token-signer.js";
import type { Pkcs11Session, KeyHandle } from "../../../../shared/hsm/pkcs11-session.js";

/**
 * HSM-backed EdDSA (Ed25519) token signer.
 *
 * The private signing key NEVER leaves the HSM boundary.
 * All Ed25519 signatures are computed inside the HSM via CKM_EDDSA.
 *
 * Output format is identical to EddsaTokenSigner:
 *   signature (64 bytes) || payload (variable length)
 *
 * This adapter is suitable for FIPS 140-3 Level 3+ deployments
 * where cryptographic keys must be protected by certified hardware.
 *
 * Key lifecycle:
 * - Key is generated or imported into the HSM during bootstrap
 * - Key is referenced by label (e.g., "ghost-token-signer-v1")
 * - Key is non-extractable (CKA_EXTRACTABLE = false)
 * - Rotation: generate new key, update label, destroy old key
 *
 * @requires A PKCS#11 session connected to an HSM that supports CKM_EDDSA.
 */
export class HsmTokenSigner implements TokenSigner {
  private constructor(
    private readonly session: Pkcs11Session,
    private readonly keyHandle: KeyHandle,
  ) {}

  /**
   * Create an HSM token signer by looking up an existing key by label.
   * Throws if the key is not found in the HSM.
   */
  static async fromLabel(
    session: Pkcs11Session,
    keyLabel: string,
  ): Promise<HsmTokenSigner> {
    const handle = await session.findKeyByLabel(keyLabel);
    if (handle === null) {
      throw new Error(
        `HSM key not found: "${keyLabel}". ` +
        "Run key ceremony to generate or import the signing key.",
      );
    }
    return new HsmTokenSigner(session, handle);
  }

  /**
   * Create an HSM token signer by generating a new Ed25519 key pair.
   * Returns the signer and the public key (for verifier configuration).
   *
   * The private key is generated inside the HSM and marked non-extractable.
   */
  static async generate(
    session: Pkcs11Session,
    keyLabel: string,
  ): Promise<{ signer: HsmTokenSigner; publicKey: Uint8Array }> {
    const { privateKeyHandle, publicKey } =
      await session.generateEd25519KeyPair({
        label: keyLabel,
        extractable: false,
        persistent: true,
      });
    return {
      signer: new HsmTokenSigner(session, privateKeyHandle),
      publicKey,
    };
  }

  /**
   * Sign token payload using Ed25519 inside the HSM.
   *
   * The private key never leaves the HSM boundary.
   * Output: signature (64 bytes) || payload (variable length).
   */
  async sign(payload: Uint8Array): Promise<Uint8Array> {
    const signature = await this.session.signEd25519(
      this.keyHandle,
      payload,
    );

    // Same output format as EddsaTokenSigner for drop-in compatibility
    const signed = new Uint8Array(signature.length + payload.length);
    signed.set(signature, 0);
    signed.set(payload, signature.length);
    return signed;
  }
}
