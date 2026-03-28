// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenVerifier } from "../../../domain/port/outgoing/token-verifier.js";

/**
 * Ed25519 signature length in bytes.
 */
const SIGNATURE_LENGTH = 64;

/**
 * EdDSA (Ed25519) implementation of TokenVerifier.
 *
 * Verifies Ed25519 signatures on signed tokens produced by EddsaTokenSigner.
 * Expected format: signature (64 bytes) || payload (variable length).
 *
 * The public key must be a 32-byte Ed25519 public key (Uint8Array).
 *
 * Returns the payload bytes if the signature is valid, null otherwise.
 * Signature verification is constant-time to prevent timing attacks.
 *
 * @requires @noble/ed25519 — installed at runtime, dynamically imported
 */
export class EddsaTokenVerifier implements TokenVerifier {
  constructor(private readonly publicKey: Uint8Array) {
    if (publicKey.length !== 32) {
      throw new Error("Ed25519 public key must be exactly 32 bytes");
    }
  }

  async verify(signedToken: Uint8Array): Promise<Uint8Array | null> {
    if (signedToken.length <= SIGNATURE_LENGTH) {
      return null;
    }

    const signature = signedToken.slice(0, SIGNATURE_LENGTH);
    const payload = signedToken.slice(SIGNATURE_LENGTH);

    try {
      const ed25519 = await import("@noble/ed25519");
      const isValid = await ed25519.verifyAsync(signature, payload, this.publicKey);
      if (!isValid) {
        return null;
      }
      return payload;
    } catch {
      // Any error during verification means the token is invalid
      return null;
    }
  }
}
