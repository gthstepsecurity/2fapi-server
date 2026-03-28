// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Tests for HSM-backed EdDSA token signer.
 *
 * Uses StubPkcs11Session to verify the adapter logic without real HSM hardware.
 * The stub uses @noble/ed25519 for Ed25519 operations.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { StubPkcs11Session } from "../../../src/shared/hsm/stub-pkcs11-session.js";
import { HsmTokenSigner } from "../../../src/api-access-control/infrastructure/adapter/outgoing/hsm-token-signer.js";
import { EddsaTokenVerifier } from "../../../src/api-access-control/infrastructure/adapter/outgoing/eddsa-token-verifier.js";

describe("HsmTokenSigner", () => {
  let session: StubPkcs11Session;

  beforeEach(() => {
    session = new StubPkcs11Session();
  });

  afterEach(async () => {
    await session.close();
  });

  // --- Key generation ---

  it("generates a key pair and returns public key", async () => {
    const { signer, publicKey } = await HsmTokenSigner.generate(
      session,
      "test-signer-key",
    );
    expect(signer).toBeDefined();
    expect(publicKey.length).toBe(32);
  });

  it("generated key is findable by label", async () => {
    await HsmTokenSigner.generate(session, "ghost-token-signer-v1");
    const handle = await session.findKeyByLabel("ghost-token-signer-v1");
    expect(handle).not.toBeNull();
  });

  // --- Signing ---

  it("signs payload and produces signature || payload format", async () => {
    const { signer } = await HsmTokenSigner.generate(session, "key1");
    const payload = new TextEncoder().encode('{"sub":"alice","exp":9999999999}');
    const signed = await signer.sign(payload);

    // 64 bytes signature + payload
    expect(signed.length).toBe(64 + payload.length);

    // Payload is intact after signature
    const extractedPayload = signed.slice(64);
    expect(extractedPayload).toEqual(payload);
  });

  it("HSM signature is verifiable by EddsaTokenVerifier", async () => {
    const { signer, publicKey } = await HsmTokenSigner.generate(
      session,
      "key2",
    );

    const payload = new TextEncoder().encode('{"sub":"bob"}');
    const signed = await signer.sign(payload);

    // Verify with standard EdDSA verifier (drop-in compatibility)
    const verifier = new EddsaTokenVerifier(publicKey);
    const recovered = await verifier.verify(signed);

    expect(recovered).not.toBeNull();
    expect(new TextDecoder().decode(recovered!)).toBe('{"sub":"bob"}');
  });

  it("different payloads produce different signatures", async () => {
    const { signer } = await HsmTokenSigner.generate(session, "key3");
    const sig1 = await signer.sign(new Uint8Array([1, 2, 3]));
    const sig2 = await signer.sign(new Uint8Array([4, 5, 6]));

    // Signatures differ
    expect(sig1.slice(0, 64)).not.toEqual(sig2.slice(0, 64));
  });

  // --- Key lookup ---

  it("fromLabel resolves existing key", async () => {
    await HsmTokenSigner.generate(session, "existing-key");
    const signer = await HsmTokenSigner.fromLabel(session, "existing-key");
    expect(signer).toBeDefined();

    // Should be able to sign
    const signed = await signer.sign(new Uint8Array([42]));
    expect(signed.length).toBeGreaterThan(64);
  });

  it("fromLabel throws if key not found", async () => {
    await expect(
      HsmTokenSigner.fromLabel(session, "nonexistent-key"),
    ).rejects.toThrow("HSM key not found");
  });

  // --- Session lifecycle ---

  it("throws on sign after session close", async () => {
    const { signer } = await HsmTokenSigner.generate(session, "key4");
    await session.close();

    await expect(
      signer.sign(new Uint8Array([1])),
    ).rejects.toThrow("session is closed");
  });
});
