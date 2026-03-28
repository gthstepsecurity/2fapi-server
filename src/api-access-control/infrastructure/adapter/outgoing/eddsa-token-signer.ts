// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenSigner } from "../../../domain/port/outgoing/token-signer.js";

/**
 * EdDSA (Ed25519) implementation of TokenSigner.
 *
 * Signs token payload bytes using the Ed25519 algorithm via @noble/ed25519.
 * The output format is: signature (64 bytes) || payload (variable length).
 * This allows the verifier to extract both the signature and original payload.
 *
 * The private key must be a 32-byte seed (Uint8Array).
 *
 * Security properties:
 * - Ed25519 provides 128-bit security level
 * - Deterministic signatures (no random nonce needed)
 * - Small signatures (64 bytes)
 * - Fast verification (<1ms)
 *
 * @requires @noble/ed25519 — installed at runtime, dynamically imported
 */
export class EddsaTokenSigner implements TokenSigner {
  constructor(private readonly privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error("Ed25519 private key must be exactly 32 bytes");
    }
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    const ed25519 = await import("@noble/ed25519");
    const signature = await ed25519.signAsync(payload, this.privateKey);

    // Output: signature (64 bytes) || payload
    const signed = new Uint8Array(signature.length + payload.length);
    signed.set(signature, 0);
    signed.set(payload, signature.length);
    return signed;
  }
}
