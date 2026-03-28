// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { UnsealVaultUseCase } from "../../../../packages/client-sdk/src/application/usecase/unseal-vault.js";
import type { CryptoEngine, EncryptedPayload } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { VaultServerGateway, UnsealResponse } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-server-gateway.js";
import type { VaultLocalStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-local-store.js";
import { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";

// --- Helpers ---

function makeVaultEntry(overrides: Partial<{
  createdAtMs: number;
  maxTtlHours: number;
  deviceId: string;
}> = {}): VaultEntry {
  return VaultEntry.create({
    iv: new Uint8Array(12).fill(1),
    ciphertext: new Uint8Array(64).fill(2),
    tag: new Uint8Array(16).fill(3),
    deviceId: overrides.deviceId ?? "dev-abc123def456",
    createdAtMs: overrides.createdAtMs ?? Date.now(),
    maxTtlHours: overrides.maxTtlHours ?? 72,
    version: 1,
  });
}

function stubCrypto(overrides: Partial<CryptoEngine> = {}): CryptoEngine {
  const secret = new Uint8Array(32).fill(0x11);
  const blinding = new Uint8Array(32).fill(0x22);
  const plaintext = new Uint8Array(64);
  plaintext.set(secret, 0);
  plaintext.set(blinding, 32);

  return {
    deriveCredential: async () => ({ secret, blinding }),
    computeCommitment: () => new Uint8Array(32),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32).fill(0xAA),
    encrypt: async () => ({
      iv: new Uint8Array(12),
      ciphertext: new Uint8Array(64),
      tag: new Uint8Array(16),
    }),
    decrypt: async () => new Uint8Array(plaintext),
    zeroize: (buf) => buf.fill(0),
    ...overrides,
  };
}

function stubServer(overrides: Partial<VaultServerGateway> = {}): VaultServerGateway {
  return {
    requestSeal: async () => ({ pepper: new Uint8Array(32), deviceId: "dev-abc123def456" }),
    requestUnseal: async () => ({
      status: "allowed" as const,
      pepper: new Uint8Array(32).fill(0xBB),
      attemptsRemaining: 3,
    }),
    reportUnsealFailure: async () => {},
    reportAuthSuccess: async () => {},
    deleteVaultRegistration: async () => {},
    ...overrides,
  };
}

function stubStore(entry: VaultEntry | null = null): VaultLocalStore & { deleted: boolean } {
  const store: VaultLocalStore & { deleted: boolean } = {
    deleted: false,
    save: () => {},
    load: () => entry,
    delete: () => { store.deleted = true; },
    exists: () => entry !== null,
  };
  return store;
}

const validRequest = {
  password: "MyD3v!ceP@ss",
  email: "alice@acme.com",
  tenantId: "tenant-1",
  clientId: "client-alice",
};

describe("UnsealVaultUseCase", () => {
  let crypto: CryptoEngine;
  let server: VaultServerGateway;
  let localStore: ReturnType<typeof stubStore>;
  let useCase: UnsealVaultUseCase;

  beforeEach(() => {
    crypto = stubCrypto();
    server = stubServer();
    localStore = stubStore(makeVaultEntry());
    useCase = new UnsealVaultUseCase(crypto, server, localStore);
  });

  // --- Happy Path ---

  it("unseals the vault and returns the derived secret", async () => {
    const result = await useCase.execute(validRequest);
    expect(result.isOk()).toBe(true);
    const response = result.unwrap();
    expect(response.secret.secret[0]).toBe(0x11);
    expect(response.secret.blinding[0]).toBe(0x22);
  });

  it("returns attempts remaining from server", async () => {
    const result = await useCase.execute(validRequest);
    expect(result.unwrap().attemptsRemaining).toBe(3);
  });

  it("requests pepper from server before decryption", async () => {
    let unsealCalled = false;
    server = stubServer({
      requestUnseal: async () => {
        unsealCalled = true;
        return { status: "allowed", pepper: new Uint8Array(32).fill(0xBB), attemptsRemaining: 3 };
      },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(unsealCalled).toBe(true);
  });

  it("derives vault key from password + server pepper", async () => {
    let derivedArgs: { password: string; pepperSnapshot: Uint8Array } | null = null;
    crypto = stubCrypto({
      deriveVaultKey: async (password, pepper) => {
        derivedArgs = { password, pepperSnapshot: new Uint8Array(pepper) };
        return new Uint8Array(32).fill(0xAA);
      },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(derivedArgs!.password).toBe("MyD3v!ceP@ss");
    expect(derivedArgs!.pepperSnapshot[0]).toBe(0xBB);
  });

  // --- Zeroization ---

  it("zeroizes pepper after key derivation", async () => {
    let pepperRef: Uint8Array | null = null;
    server = stubServer({
      requestUnseal: async () => {
        const pepper = new Uint8Array(32).fill(0xBB);
        pepperRef = pepper;
        return { status: "allowed", pepper, attemptsRemaining: 3 };
      },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(pepperRef!.every(b => b === 0)).toBe(true);
  });

  it("zeroizes vault key after decryption", async () => {
    let keyRef: Uint8Array | null = null;
    crypto = stubCrypto({
      deriveVaultKey: async () => {
        const key = new Uint8Array(32).fill(0xAA);
        keyRef = key;
        return key;
      },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(keyRef!.every(b => b === 0)).toBe(true);
  });

  // --- Error Cases ---

  it("returns NO_VAULT_FOUND when no vault in localStorage", async () => {
    localStore = stubStore(null);
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("NO_VAULT_FOUND");
  });

  it("returns VAULT_EXPIRED when vault TTL exceeded", async () => {
    const expiredEntry = makeVaultEntry({
      createdAtMs: Date.now() - 73 * 60 * 60 * 1000,
      maxTtlHours: 72,
    });
    localStore = stubStore(expiredEntry);
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("VAULT_EXPIRED");
  });

  it("deletes expired vault from localStorage", async () => {
    const expiredEntry = makeVaultEntry({
      createdAtMs: Date.now() - 73 * 60 * 60 * 1000,
    });
    localStore = stubStore(expiredEntry);
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(localStore.deleted).toBe(true);
  });

  it("returns VAULT_WIPED when server says wiped", async () => {
    server = stubServer({
      requestUnseal: async () => ({ status: "wiped" }),
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("VAULT_WIPED");
  });

  it("deletes vault when server says wiped", async () => {
    server = stubServer({
      requestUnseal: async () => ({ status: "wiped" }),
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(localStore.deleted).toBe(true);
  });

  it("returns SERVER_UNREACHABLE when server is offline", async () => {
    server = stubServer({
      requestUnseal: async () => { throw new Error("network"); },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("SERVER_UNREACHABLE");
  });

  it("does NOT attempt decryption when server is offline", async () => {
    let decryptCalled = false;
    crypto = stubCrypto({
      decrypt: async () => { decryptCalled = true; return new Uint8Array(64); },
    });
    server = stubServer({
      requestUnseal: async () => { throw new Error("network"); },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(decryptCalled).toBe(false);
  });

  it("returns WRONG_PASSWORD when decryption fails (GCM tag mismatch)", async () => {
    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("WRONG_PASSWORD");
  });

  it("reports unseal failure to server when password is wrong", async () => {
    let failureReported = false;
    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    server = stubServer({
      requestUnseal: async () => ({
        status: "allowed",
        pepper: new Uint8Array(32).fill(0xBB),
        attemptsRemaining: 2,
      }),
      reportUnsealFailure: async () => { failureReported = true; },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(failureReported).toBe(true);
  });

  it("does not delete vault on wrong password (user can retry)", async () => {
    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    useCase = new UnsealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(localStore.deleted).toBe(false);
  });
});
