// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: normalizes WebCrypto syscall footprint across all tiers (R22-01 fix).
 *
 * Instead of moving AES-GCM from WebCrypto to WASM (which loses AES-NI
 * hardware constant-time guarantees), we ADD a dummy WebCrypto call to
 * tiers that don't need AES-GCM.
 *
 * Result: ALL tiers produce the same BoringSSL/OpenSSL syscall trace
 * (ioctl for AES-NI + getrandom for IV), AND we keep hardware AES-NI.
 *
 * Also batches ALL randomness into a single getrandom call (R22-02 fix).
 */
export class CryptoNormalizer {
  constructor(
    private readonly crypto: CryptoOperations,
  ) {}

  /**
   * Generate all needed random bytes in a SINGLE call.
   * R22-02: one getrandom(128) regardless of tier.
   */
  async batchRandom(): Promise<RandomBatch> {
    const all = new Uint8Array(128);
    this.crypto.getRandomValues(all);
    return {
      oprfBlinding: all.slice(0, 64),
      proofNonces: all.slice(64, 96),
      aesIv: all.slice(96, 108),
      reserved: all.slice(108, 128),
      zeroize: () => all.fill(0),
    };
  }

  /**
   * Execute a dummy AES-256-GCM encrypt+decrypt cycle via WebCrypto.
   * R22-01: produces the same BoringSSL syscall trace as a real vault decrypt.
   * The dummy key, IV, and plaintext are random — the output is discarded.
   */
  async dummyAesGcm(): Promise<void> {
    const key = new Uint8Array(32);
    const iv = new Uint8Array(12);
    const plaintext = new Uint8Array(64); // same size as real vault content
    this.crypto.getRandomValues(key);
    this.crypto.getRandomValues(iv);
    this.crypto.getRandomValues(plaintext);

    // Import key → encrypt → decrypt (full round-trip = same syscall pattern)
    const cryptoKey = await this.crypto.importKey(key);
    const encrypted = await this.crypto.encrypt(cryptoKey, iv, plaintext);
    await this.crypto.decrypt(cryptoKey, iv, encrypted);

    // Zeroize
    key.fill(0);
    iv.fill(0);
    plaintext.fill(0);
  }
}

export interface CryptoOperations {
  getRandomValues(buffer: Uint8Array): void;
  importKey(raw: Uint8Array): Promise<CryptoKey>;
  encrypt(key: CryptoKey, iv: Uint8Array, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(key: CryptoKey, iv: Uint8Array, data: ArrayBuffer): Promise<ArrayBuffer>;
}

export interface RandomBatch {
  readonly oprfBlinding: Uint8Array;
  readonly proofNonces: Uint8Array;
  readonly aesIv: Uint8Array;
  readonly reserved: Uint8Array;
  zeroize(): void;
}
