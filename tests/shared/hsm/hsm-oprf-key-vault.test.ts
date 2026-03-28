// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Tests for HSM-backed OPRF key vault.
 *
 * Verifies that OPRF keys are stored in the HSM and only extracted
 * for the minimum time needed for scalar multiplication.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { StubPkcs11Session } from "../../../src/shared/hsm/stub-pkcs11-session.js";
import { HsmOprfKeyVault } from "../../../src/shared/hsm/hsm-oprf-key-vault.js";

// Stub OPRF evaluator: simple XOR for testing (not real Ristretto math)
function stubEvaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array {
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = (blindedPoint[i] ?? 0) ^ (oprfKey[i] ?? 0);
  }
  return result;
}

function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

describe("HsmOprfKeyVault", () => {
  let session: StubPkcs11Session;
  let vault: HsmOprfKeyVault;

  beforeEach(() => {
    session = new StubPkcs11Session();
    vault = new HsmOprfKeyVault(session, stubEvaluate, zeroize);
  });

  afterEach(async () => {
    await session.close();
  });

  // --- Key generation ---

  it("generates an OPRF key in the HSM", async () => {
    await vault.generateKey("oprf-tenant-1-alice");
    const exists = await vault.hasKey("oprf-tenant-1-alice");
    expect(exists).toBe(true);
  });

  it("key is findable by label after generation", async () => {
    await vault.generateKey("oprf-key-42");
    const handle = await session.findKeyByLabel("oprf-key-42");
    expect(handle).not.toBeNull();
  });

  it("generated key is 32 bytes", async () => {
    await vault.generateKey("oprf-size-check");
    const handle = await session.findKeyByLabel("oprf-size-check");
    const data = await session.retrieveOpaqueSecret(handle!);
    expect(data.length).toBe(32);
  });

  // --- OPRF evaluation ---

  it("evaluates OPRF with HSM-stored key", async () => {
    await vault.generateKey("oprf-eval-test");
    const blindedPoint = new Uint8Array(32).fill(0xAA);

    const result = await vault.evaluate("oprf-eval-test", blindedPoint);

    // Result should not be all zeros (key XOR 0xAA)
    expect(result.length).toBe(32);
    expect(result.some((b) => b !== 0)).toBe(true);
  });

  it("same key + same input = same output (deterministic)", async () => {
    await vault.generateKey("oprf-determ");
    const input = new Uint8Array(32).fill(0xBB);

    const r1 = await vault.evaluate("oprf-determ", input);
    const r2 = await vault.evaluate("oprf-determ", input);

    expect(r1).toEqual(r2);
  });

  it("different keys + same input = different output", async () => {
    await vault.generateKey("oprf-key-a");
    await vault.generateKey("oprf-key-b");
    const input = new Uint8Array(32).fill(0xCC);

    const ra = await vault.evaluate("oprf-key-a", input);
    const rb = await vault.evaluate("oprf-key-b", input);

    expect(ra).not.toEqual(rb);
  });

  it("throws if key not found", async () => {
    await expect(
      vault.evaluate("nonexistent-key", new Uint8Array(32)),
    ).rejects.toThrow("OPRF key not found in HSM");
  });

  // --- Key zeroization ---

  it("key is zeroized after evaluation", async () => {
    let capturedKey: Uint8Array | null = null;

    const spyEvaluate = (bp: Uint8Array, key: Uint8Array): Uint8Array => {
      capturedKey = key; // Capture reference to key buffer
      return stubEvaluate(bp, key);
    };

    const spyVault = new HsmOprfKeyVault(session, spyEvaluate, zeroize);
    await spyVault.generateKey("oprf-zeroize-test");
    await spyVault.evaluate("oprf-zeroize-test", new Uint8Array(32));

    // After evaluate returns, the key buffer should be zeroized
    expect(capturedKey).not.toBeNull();
    expect(capturedKey!.every((b) => b === 0)).toBe(true);
  });

  it("key is zeroized even if evaluation throws", async () => {
    let capturedKey: Uint8Array | null = null;

    const throwingEvaluate = (_bp: Uint8Array, key: Uint8Array): Uint8Array => {
      capturedKey = key;
      throw new Error("evaluation failed");
    };

    const throwVault = new HsmOprfKeyVault(session, throwingEvaluate, zeroize);
    await throwVault.generateKey("oprf-throw-test");

    await expect(
      throwVault.evaluate("oprf-throw-test", new Uint8Array(32)),
    ).rejects.toThrow("evaluation failed");

    // Key MUST still be zeroized
    expect(capturedKey).not.toBeNull();
    expect(capturedKey!.every((b) => b === 0)).toBe(true);
  });

  // --- Key destruction ---

  it("destroyKey removes key from HSM", async () => {
    await vault.generateKey("oprf-destroy");
    expect(await vault.hasKey("oprf-destroy")).toBe(true);

    await vault.destroyKey("oprf-destroy");
    expect(await vault.hasKey("oprf-destroy")).toBe(false);
  });

  it("destroyKey is idempotent (no-op if key not found)", async () => {
    await expect(vault.destroyKey("nonexistent")).resolves.not.toThrow();
  });

  // --- Key rotation ---

  it("rotateKey generates a new key with -next suffix", async () => {
    await vault.generateKey("oprf-rotate");
    await vault.rotateKey("oprf-rotate");

    expect(await vault.hasKey("oprf-rotate")).toBe(true);
    expect(await vault.hasKey("oprf-rotate-next")).toBe(true);
  });

  // --- Session lifecycle ---

  it("throws on evaluate after session close", async () => {
    await vault.generateKey("oprf-close");
    await session.close();

    await expect(
      vault.evaluate("oprf-close", new Uint8Array(32)),
    ).rejects.toThrow("session is closed");
  });
});
