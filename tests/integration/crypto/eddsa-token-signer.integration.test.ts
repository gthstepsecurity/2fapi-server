// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";

/**
 * Integration tests for EddsaTokenSigner and EddsaTokenVerifier.
 *
 * Requires: @noble/ed25519 npm package
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("EdDSA Token Signer/Verifier [integration]", () => {
  it("should sign and verify a payload", async () => {
    const ed25519 = await import("@noble/ed25519");
    const { EddsaTokenSigner } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-signer.js"
    );
    const { EddsaTokenVerifier } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js"
    );

    // Generate a key pair
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKeyAsync(privateKey);

    const signer = new EddsaTokenSigner(privateKey);
    const verifier = new EddsaTokenVerifier(publicKey);

    const payload = new TextEncoder().encode('{"sub":"alice","aud":"test"}');

    const signed = await signer.sign(payload);
    expect(signed.length).toBe(64 + payload.length);

    const verified = await verifier.verify(signed);
    expect(verified).not.toBeNull();
    expect(verified).toEqual(payload);
  });

  it("should reject a tampered payload", async () => {
    const ed25519 = await import("@noble/ed25519");
    const { EddsaTokenSigner } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-signer.js"
    );
    const { EddsaTokenVerifier } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js"
    );

    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKeyAsync(privateKey);

    const signer = new EddsaTokenSigner(privateKey);
    const verifier = new EddsaTokenVerifier(publicKey);

    const payload = new TextEncoder().encode("original");
    const signed = await signer.sign(payload);

    // Tamper with payload bytes
    signed[65] = (signed[65]! ^ 0xFF);

    const verified = await verifier.verify(signed);
    expect(verified).toBeNull();
  });

  it("should reject a token signed with a different key", async () => {
    const ed25519 = await import("@noble/ed25519");
    const { EddsaTokenSigner } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-signer.js"
    );
    const { EddsaTokenVerifier } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js"
    );

    const privateKey1 = ed25519.utils.randomPrivateKey();
    const privateKey2 = ed25519.utils.randomPrivateKey();
    const publicKey2 = await ed25519.getPublicKeyAsync(privateKey2);

    const signer = new EddsaTokenSigner(privateKey1);
    const verifier = new EddsaTokenVerifier(publicKey2);

    const payload = new TextEncoder().encode("test payload");
    const signed = await signer.sign(payload);

    const verified = await verifier.verify(signed);
    expect(verified).toBeNull();
  });

  it("should reject tokens that are too short", async () => {
    const ed25519 = await import("@noble/ed25519");
    const { EddsaTokenVerifier } = await import(
      "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js"
    );

    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKeyAsync(privateKey);
    const verifier = new EddsaTokenVerifier(publicKey);

    // Token shorter than 64 bytes (signature length)
    const tooShort = new Uint8Array(32);
    const verified = await verifier.verify(tooShort);
    expect(verified).toBeNull();
  });
});
