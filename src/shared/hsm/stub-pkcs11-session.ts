// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  Pkcs11Session,
  KeyHandle,
  KeyAttributes,
} from "./pkcs11-session.js";

/**
 * In-memory stub PKCS#11 session for testing and development.
 *
 * Simulates HSM key storage and operations using in-memory maps.
 * NOT constant-time — use only for functional testing.
 * For constant-time verification, use dudect with the real crypto adapters.
 *
 * @warning NEVER use in production. This provides ZERO hardware protection.
 */
export class StubPkcs11Session implements Pkcs11Session {
  private nextHandle: bigint = 1n;
  private readonly keys = new Map<
    bigint,
    { label: string; data: Uint8Array; attrs: KeyAttributes }
  >();
  private closed = false;

  private assertOpen(): void {
    if (this.closed) {
      throw new Error("PKCS#11 session is closed");
    }
  }

  private allocHandle(): KeyHandle {
    return this.nextHandle++;
  }

  async generateEd25519KeyPair(
    attrs: KeyAttributes,
  ): Promise<{ privateKeyHandle: KeyHandle; publicKey: Uint8Array }> {
    this.assertOpen();

    // Generate random 32-byte Ed25519 seed
    const privateKey = new Uint8Array(32);
    globalThis.crypto.getRandomValues(privateKey);

    // Derive public key (simplified stub — real HSM uses CKM_EDDSA)
    const ed25519 = await import("@noble/ed25519");
    const publicKey = await ed25519.getPublicKeyAsync(privateKey);

    const handle = this.allocHandle();
    this.keys.set(handle, {
      label: attrs.label,
      data: new Uint8Array(privateKey),
      attrs,
    });

    return { privateKeyHandle: handle, publicKey: new Uint8Array(publicKey) };
  }

  async importEd25519PrivateKey(
    privateKey: Uint8Array,
    attrs: KeyAttributes,
  ): Promise<KeyHandle> {
    this.assertOpen();
    if (privateKey.length !== 32) {
      throw new Error("Ed25519 private key must be 32 bytes");
    }

    const handle = this.allocHandle();
    this.keys.set(handle, {
      label: attrs.label,
      data: new Uint8Array(privateKey),
      attrs,
    });
    return handle;
  }

  async signEd25519(
    keyHandle: KeyHandle,
    payload: Uint8Array,
  ): Promise<Uint8Array> {
    this.assertOpen();
    const entry = this.keys.get(keyHandle);
    if (!entry) {
      throw new Error(`Key handle ${keyHandle} not found`);
    }

    const ed25519 = await import("@noble/ed25519");
    const signature = await ed25519.signAsync(payload, entry.data);
    return new Uint8Array(signature);
  }

  async findKeyByLabel(label: string): Promise<KeyHandle | null> {
    this.assertOpen();
    for (const [handle, entry] of this.keys) {
      if (entry.label === label) {
        return handle;
      }
    }
    return null;
  }

  async storeOpaqueSecret(
    data: Uint8Array,
    attrs: KeyAttributes,
  ): Promise<KeyHandle> {
    this.assertOpen();
    const handle = this.allocHandle();
    this.keys.set(handle, {
      label: attrs.label,
      data: new Uint8Array(data),
      attrs,
    });
    return handle;
  }

  async retrieveOpaqueSecret(handle: KeyHandle): Promise<Uint8Array> {
    this.assertOpen();
    const entry = this.keys.get(handle);
    if (!entry) {
      throw new Error(`Key handle ${handle} not found`);
    }
    if (!entry.attrs.extractable) {
      throw new Error("Key is not extractable (CKA_EXTRACTABLE=false)");
    }
    return new Uint8Array(entry.data);
  }

  async destroyObject(handle: KeyHandle): Promise<void> {
    this.assertOpen();
    this.keys.delete(handle);
  }

  async close(): Promise<void> {
    this.keys.clear();
    this.closed = true;
  }
}
