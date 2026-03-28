// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { webcrypto } from "node:crypto";
import { WebCryptoCryptoEngine } from "../../../../../packages/client-sdk/src/infrastructure/adapter/outgoing/web-crypto-engine.js";

// Node.js provides SubtleCrypto via webcrypto — same API as browser
const engine = new WebCryptoCryptoEngine(webcrypto as unknown as Crypto);

describe("WebCryptoCryptoEngine", () => {
  // --- Vault Key Derivation (HKDF) ---

  describe("deriveVaultKey", () => {
    it("derives a 256-bit key from password + pepper", async () => {
      const pepper = new Uint8Array(32).fill(0xBB);
      const key = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", pepper, "dev-abc123", "alice@acme.com", "tenant-1",
      );
      expect(key.length).toBe(32);
      expect(key.some(b => b !== 0)).toBe(true);
    });

    it("is deterministic for same inputs", async () => {
      const pepper = new Uint8Array(32).fill(0xBB);
      const key1 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", pepper, "dev-abc123", "alice@acme.com", "tenant-1",
      );
      const key2 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", new Uint8Array(32).fill(0xBB), "dev-abc123", "alice@acme.com", "tenant-1",
      );
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(true);
    });

    it("produces different keys for different passwords", async () => {
      const pepper = new Uint8Array(32).fill(0xBB);
      const key1 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", pepper, "dev-abc123", "alice@acme.com", "tenant-1",
      );
      const key2 = await engine.deriveVaultKey(
        "DifferentPwd!", new Uint8Array(32).fill(0xBB), "dev-abc123", "alice@acme.com", "tenant-1",
      );
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it("produces different keys for different peppers", async () => {
      const key1 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", new Uint8Array(32).fill(0xAA), "dev-abc123", "alice@acme.com", "tenant-1",
      );
      const key2 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", new Uint8Array(32).fill(0xBB), "dev-abc123", "alice@acme.com", "tenant-1",
      );
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it("produces different keys for different device IDs", async () => {
      const pepper = new Uint8Array(32).fill(0xBB);
      const key1 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", pepper, "dev-aaa111", "alice@acme.com", "tenant-1",
      );
      const key2 = await engine.deriveVaultKey(
        "MyD3v!ceP@ss", new Uint8Array(32).fill(0xBB), "dev-bbb222", "alice@acme.com", "tenant-1",
      );
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
  });

  // --- AES-256-GCM Encrypt/Decrypt ---

  describe("encrypt / decrypt", () => {
    it("roundtrips plaintext correctly", async () => {
      const key = new Uint8Array(32).fill(0xAA);
      const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const encrypted = await engine.encrypt(key, plaintext);
      const decrypted = await engine.decrypt(key, encrypted);

      expect(Buffer.from(decrypted).equals(Buffer.from(plaintext))).toBe(true);
    });

    it("produces different ciphertext for same plaintext (random IV)", async () => {
      const key = new Uint8Array(32).fill(0xAA);
      const plaintext = new Uint8Array(64).fill(0x42);

      const enc1 = await engine.encrypt(key, plaintext);
      const enc2 = await engine.encrypt(key, plaintext);

      // IVs should differ (random)
      expect(Buffer.from(enc1.iv).equals(Buffer.from(enc2.iv))).toBe(false);
    });

    it("fails to decrypt with wrong key", async () => {
      const key1 = new Uint8Array(32).fill(0xAA);
      const key2 = new Uint8Array(32).fill(0xBB);
      const plaintext = new Uint8Array(64).fill(0x42);

      const encrypted = await engine.encrypt(key1, plaintext);

      await expect(engine.decrypt(key2, encrypted)).rejects.toThrow();
    });

    it("fails to decrypt with tampered ciphertext", async () => {
      const key = new Uint8Array(32).fill(0xAA);
      const plaintext = new Uint8Array(64).fill(0x42);

      const encrypted = await engine.encrypt(key, plaintext);
      // Tamper with ciphertext
      const tampered = {
        ...encrypted,
        ciphertext: new Uint8Array(encrypted.ciphertext),
      };
      tampered.ciphertext[0] ^= 0xFF;

      await expect(engine.decrypt(key, tampered)).rejects.toThrow();
    });

    it("IV is 12 bytes", async () => {
      const key = new Uint8Array(32).fill(0xAA);
      const encrypted = await engine.encrypt(key, new Uint8Array(32));
      expect(encrypted.iv.length).toBe(12);
    });

    it("tag is 16 bytes", async () => {
      const key = new Uint8Array(32).fill(0xAA);
      const encrypted = await engine.encrypt(key, new Uint8Array(32));
      expect(encrypted.tag.length).toBe(16);
    });
  });

  // --- Zeroize ---

  describe("zeroize", () => {
    it("overwrites buffer with zeros", () => {
      const buf = new Uint8Array(32).fill(0xFF);
      engine.zeroize(buf);
      expect(buf.every(b => b === 0)).toBe(true);
    });

    it("handles empty buffer", () => {
      const buf = new Uint8Array(0);
      engine.zeroize(buf);
      expect(buf.length).toBe(0);
    });
  });
});
