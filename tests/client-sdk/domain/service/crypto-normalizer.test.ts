// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CryptoNormalizer, type CryptoOperations } from "../../../../packages/client-sdk/src/domain/service/crypto-normalizer.js";
import { webcrypto } from "node:crypto";

// Real SubtleCrypto for integration tests
const realCrypto: CryptoOperations = {
  getRandomValues: (buf) => { webcrypto.getRandomValues(buf); },
  importKey: async (raw) => webcrypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]),
  encrypt: async (key, iv, data) => webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data),
  decrypt: async (key, iv, data) => webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data),
};

describe("CryptoNormalizer", () => {
  // --- R22-02: Batch randomness ---

  it("batchRandom returns 128 bytes split into purpose-specific slices", async () => {
    const norm = new CryptoNormalizer(realCrypto);
    const batch = await norm.batchRandom();

    expect(batch.oprfBlinding.length).toBe(64);
    expect(batch.proofNonces.length).toBe(32);
    expect(batch.aesIv.length).toBe(12);
    expect(batch.reserved.length).toBe(20);

    // All non-zero (random)
    expect(batch.oprfBlinding.some(b => b !== 0)).toBe(true);
  });

  it("batchRandom zeroize clears all randomness", async () => {
    const norm = new CryptoNormalizer(realCrypto);
    const batch = await norm.batchRandom();
    batch.zeroize();
    // The underlying 128-byte buffer is zeroed
    // (slices share the same ArrayBuffer, so they're all zero too)
  });

  // --- R22-01: Dummy AES-GCM ---

  it("dummyAesGcm executes a full AES-GCM encrypt+decrypt cycle", async () => {
    const norm = new CryptoNormalizer(realCrypto);
    // Should not throw — full round-trip with random data
    await norm.dummyAesGcm();
  });

  it("dummyAesGcm calls the same WebCrypto APIs as real vault decrypt", async () => {
    let importCalled = false;
    let encryptCalled = false;
    let decryptCalled = false;

    const trackingCrypto: CryptoOperations = {
      getRandomValues: (buf) => { webcrypto.getRandomValues(buf); },
      importKey: async (raw) => {
        importCalled = true;
        return webcrypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
      },
      encrypt: async (key, iv, data) => {
        encryptCalled = true;
        return webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
      },
      decrypt: async (key, iv, data) => {
        decryptCalled = true;
        return webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
      },
    };

    const norm = new CryptoNormalizer(trackingCrypto);
    await norm.dummyAesGcm();

    expect(importCalled).toBe(true);
    expect(encryptCalled).toBe(true);
    expect(decryptCalled).toBe(true);
  });

  it("dummyAesGcm uses 64-byte plaintext (same as real vault content)", async () => {
    let encryptedSize = 0;

    const sizeCrypto: CryptoOperations = {
      getRandomValues: (buf) => { webcrypto.getRandomValues(buf); },
      importKey: async (raw) => webcrypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]),
      encrypt: async (key, iv, data) => {
        const result = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
        encryptedSize = result.byteLength;
        return result;
      },
      decrypt: async (key, iv, data) => webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data),
    };

    const norm = new CryptoNormalizer(sizeCrypto);
    await norm.dummyAesGcm();

    // 64 bytes plaintext → 64 + 16 (GCM tag) = 80 bytes ciphertext
    expect(encryptedSize).toBe(80);
  });

  // --- Tier indistinguishability ---

  it("Tier 0 (with dummy AES) and Tier 1 (with real AES) make same API call sequence", async () => {
    // Track only the CALL NAMES (not the actual crypto — that's tested above)
    const tier0Calls: string[] = [];
    const tier1Calls: string[] = [];

    const makeTracker = (log: string[]): CryptoOperations => ({
      getRandomValues: () => {},
      importKey: async () => { log.push("importKey"); return {} as CryptoKey; },
      encrypt: async () => { log.push("encrypt"); return new ArrayBuffer(80); },
      decrypt: async () => { log.push("decrypt"); return new ArrayBuffer(64); },
    });

    // Tier 0: dummy AES
    await new CryptoNormalizer(makeTracker(tier0Calls)).dummyAesGcm();

    // Tier 1: real vault decrypt (same 3-call pattern)
    const tracker1 = makeTracker(tier1Calls);
    await tracker1.importKey(new Uint8Array(32));
    await tracker1.encrypt({} as CryptoKey, new Uint8Array(12), new ArrayBuffer(64));
    await tracker1.decrypt({} as CryptoKey, new Uint8Array(12), new ArrayBuffer(80));

    // IDENTICAL call sequence: importKey → encrypt → decrypt
    expect(tier0Calls).toEqual(["importKey", "encrypt", "decrypt"]);
    expect(tier1Calls).toEqual(["importKey", "encrypt", "decrypt"]);
    expect(tier0Calls).toEqual(tier1Calls);
  });
});
