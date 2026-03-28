// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { SealVaultUseCase } from "../../../../packages/client-sdk/src/application/usecase/seal-vault.js";
import type { CryptoEngine, DerivedSecret, EncryptedPayload } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { VaultServerGateway, SealResponse } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-server-gateway.js";
import type { VaultLocalStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-local-store.js";
import type { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";

// --- Stubs ---

function stubCryptoEngine(overrides: Partial<CryptoEngine> = {}): CryptoEngine {
  return {
    deriveCredential: async () => ({ secret: new Uint8Array(32), blinding: new Uint8Array(32) }),
    computeCommitment: () => new Uint8Array(32),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32).fill(0xAA),
    encrypt: async () => ({
      iv: new Uint8Array(12).fill(1),
      ciphertext: new Uint8Array(64).fill(2),
      tag: new Uint8Array(16).fill(3),
    }),
    decrypt: async () => new Uint8Array(64),
    zeroize: (buf) => buf.fill(0),
    ...overrides,
  };
}

function stubServerGateway(overrides: Partial<VaultServerGateway> = {}): VaultServerGateway {
  return {
    requestSeal: async () => ({
      pepper: new Uint8Array(32).fill(0xBB),
      deviceId: "dev-abc123def456",
    }),
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

function stubLocalStore(): VaultLocalStore & { saved: VaultEntry | null } {
  const store: VaultLocalStore & { saved: VaultEntry | null } = {
    saved: null,
    save: (email, entry) => { store.saved = entry; },
    load: () => store.saved,
    delete: () => { store.saved = null; },
    exists: () => store.saved !== null,
  };
  return store;
}

const validRequest = {
  password: "MyD3v!ceP@ss",
  passwordConfirmation: "MyD3v!ceP@ss",
  secret: new Uint8Array(32).fill(0x11),
  blinding: new Uint8Array(32).fill(0x22),
  email: "alice@acme.com",
  tenantId: "tenant-1",
  clientId: "client-alice",
  deviceId: "dev-abc123def456",
};

describe("SealVaultUseCase", () => {
  let crypto: CryptoEngine;
  let server: VaultServerGateway;
  let localStore: ReturnType<typeof stubLocalStore>;
  let useCase: SealVaultUseCase;

  beforeEach(() => {
    crypto = stubCryptoEngine();
    server = stubServerGateway();
    localStore = stubLocalStore();
    useCase = new SealVaultUseCase(crypto, server, localStore);
  });

  it("seals the vault successfully with matching passwords", async () => {
    const result = await useCase.execute(validRequest);
    expect(result.isOk()).toBe(true);
    expect(result.unwrap().deviceId).toBe("dev-abc123def456");
  });

  it("stores the encrypted vault in local storage", async () => {
    await useCase.execute(validRequest);
    expect(localStore.saved).not.toBeNull();
    expect(localStore.saved!.deviceId).toBe("dev-abc123def456");
  });

  it("requests a pepper from the server", async () => {
    let sealCalled = false;
    server = stubServerGateway({
      requestSeal: async () => {
        sealCalled = true;
        return { pepper: new Uint8Array(32).fill(0xBB), deviceId: "dev-abc123def456" };
      },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(sealCalled).toBe(true);
  });

  it("derives vault key from password + pepper", async () => {
    let derivedWith: { password: string; pepperSnapshot: Uint8Array } | null = null;
    crypto = stubCryptoEngine({
      deriveVaultKey: async (password, pepper) => {
        derivedWith = { password, pepperSnapshot: new Uint8Array(pepper) };
        return new Uint8Array(32).fill(0xAA);
      },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(derivedWith).not.toBeNull();
    expect(derivedWith!.password).toBe("MyD3v!ceP@ss");
    expect(derivedWith!.pepperSnapshot[0]).toBe(0xBB);
  });

  it("zeroizes the pepper after key derivation", async () => {
    let pepperRef: Uint8Array | null = null;
    server = stubServerGateway({
      requestSeal: async () => {
        const pepper = new Uint8Array(32).fill(0xBB);
        pepperRef = pepper;
        return { pepper, deviceId: "dev-abc123def456" };
      },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(pepperRef).not.toBeNull();
    expect(pepperRef!.every(b => b === 0)).toBe(true);
  });

  it("zeroizes the vault key after encryption", async () => {
    let vaultKeyRef: Uint8Array | null = null;
    crypto = stubCryptoEngine({
      deriveVaultKey: async () => {
        const key = new Uint8Array(32).fill(0xAA);
        vaultKeyRef = key;
        return key;
      },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(vaultKeyRef).not.toBeNull();
    expect(vaultKeyRef!.every(b => b === 0)).toBe(true);
  });

  it("rejects when password is too short", async () => {
    const result = await useCase.execute({ ...validRequest, password: "abc", passwordConfirmation: "abc" });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PASSWORD_TOO_SHORT");
  });

  it("rejects when passwords do not match", async () => {
    const result = await useCase.execute({ ...validRequest, passwordConfirmation: "Different1!" });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PASSWORDS_DO_NOT_MATCH");
  });

  it("returns SERVER_UNREACHABLE when server fails", async () => {
    server = stubServerGateway({
      requestSeal: async () => { throw new Error("network error"); },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("SERVER_UNREACHABLE");
  });

  it("does not store vault when server fails", async () => {
    server = stubServerGateway({
      requestSeal: async () => { throw new Error("network error"); },
    });
    useCase = new SealVaultUseCase(crypto, server, localStore);

    await useCase.execute(validRequest);
    expect(localStore.saved).toBeNull();
  });
});
