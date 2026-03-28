// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { SealVaultOprfUseCase } from "../../../../packages/client-sdk/src/application/usecase/seal-vault-oprf.js";
import type { CryptoEngine } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../../../packages/client-sdk/src/domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-local-store.js";
import type { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";

function stubCrypto(overrides: Partial<CryptoEngine> = {}): CryptoEngine {
  return {
    deriveCredential: async () => ({ secret: new Uint8Array(32), blinding: new Uint8Array(32) }),
    computeCommitment: () => new Uint8Array(32),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32).fill(0xAA),
    encrypt: async () => ({ iv: new Uint8Array(12).fill(1), ciphertext: new Uint8Array(64).fill(2), tag: new Uint8Array(16).fill(3) }),
    decrypt: async () => new Uint8Array(64),
    zeroize: (buf) => buf.fill(0),
    oprfBlind: () => ({ blindedPoint: new Uint8Array(32).fill(0xBB), blindingFactor: new Uint8Array(32).fill(0xCC) }),
    oprfUnblind: () => new Uint8Array(32).fill(0xDD),
    deriveVaultKeyFromOprf: async () => new Uint8Array(32).fill(0xAA),
    ...overrides,
  };
}

function stubOprfGateway(overrides: Partial<OprfGateway> = {}): OprfGateway {
  return {
    requestEvaluation: async () => ({
      status: "allowed" as const,
      evaluated: new Uint8Array(32).fill(0xEE),
      attemptsRemaining: 3,
    }),
    reportFailure: async () => {},
    ...overrides,
  };
}

function stubLocalStore(): VaultLocalStore & { saved: VaultEntry | null } {
  const store: VaultLocalStore & { saved: VaultEntry | null } = {
    saved: null,
    save: (_email, entry) => { store.saved = entry; },
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
  deviceId: "dev-abc123",
};

describe("SealVaultOprfUseCase", () => {
  let crypto: CryptoEngine;
  let gateway: OprfGateway;
  let store: ReturnType<typeof stubLocalStore>;
  let useCase: SealVaultOprfUseCase;

  beforeEach(() => {
    crypto = stubCrypto();
    gateway = stubOprfGateway();
    store = stubLocalStore();
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);
  });

  it("seals vault via OPRF — server never sees password", async () => {
    const result = await useCase.execute(validRequest);
    expect(result.isOk()).toBe(true);
    expect(result.unwrap().deviceId).toBe("dev-abc123");
  });

  it("stores encrypted vault in localStorage", async () => {
    await useCase.execute(validRequest);
    expect(store.saved).not.toBeNull();
    expect(store.saved!.deviceId).toBe("dev-abc123");
    expect(store.saved!.version).toBe(2);
  });

  it("blinds password before sending to server", async () => {
    let capturedBlinded: Uint8Array | null = null;
    gateway = stubOprfGateway({
      requestEvaluation: async (params) => {
        capturedBlinded = params.blindedPoint;
        return { status: "allowed", evaluated: new Uint8Array(32).fill(0xEE), attemptsRemaining: 3 };
      },
    });
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);

    await useCase.execute(validRequest);
    expect(capturedBlinded).not.toBeNull();
    expect(capturedBlinded![0]).toBe(0xBB);
  });

  it("derives vault key from OPRF output (not plaintext pepper)", async () => {
    let oprfOutputSnapshot: Uint8Array | null = null;
    crypto = stubCrypto({
      deriveVaultKeyFromOprf: async (oprfOutput) => {
        oprfOutputSnapshot = new Uint8Array(oprfOutput);
        return new Uint8Array(32).fill(0xAA);
      },
    });
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);

    await useCase.execute(validRequest);
    expect(oprfOutputSnapshot![0]).toBe(0xDD); // unblinded OPRF output
  });

  it("zeroizes OPRF output and vault key after seal", async () => {
    let oprfRef: Uint8Array | null = null;
    let keyRef: Uint8Array | null = null;
    crypto = stubCrypto({
      oprfUnblind: () => { const u = new Uint8Array(32).fill(0xDD); oprfRef = u; return u; },
      deriveVaultKeyFromOprf: async () => { const k = new Uint8Array(32).fill(0xAA); keyRef = k; return k; },
    });
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);

    await useCase.execute(validRequest);
    expect(oprfRef!.every(b => b === 0)).toBe(true);
    expect(keyRef!.every(b => b === 0)).toBe(true);
  });

  it("rejects password shorter than 8 chars", async () => {
    const result = await useCase.execute({ ...validRequest, password: "abc", passwordConfirmation: "abc" });
    expect(result.unwrapErr()).toBe("PASSWORD_TOO_SHORT");
  });

  it("rejects mismatched passwords", async () => {
    const result = await useCase.execute({ ...validRequest, passwordConfirmation: "Different1!" });
    expect(result.unwrapErr()).toBe("PASSWORDS_DO_NOT_MATCH");
  });

  it("returns SERVER_UNREACHABLE when OPRF server fails", async () => {
    gateway = stubOprfGateway({
      requestEvaluation: async () => { throw new Error("network"); },
    });
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);

    const result = await useCase.execute(validRequest);
    expect(result.unwrapErr()).toBe("SERVER_UNREACHABLE");
  });

  it("does not store vault when server fails", async () => {
    gateway = stubOprfGateway({
      requestEvaluation: async () => { throw new Error("network"); },
    });
    useCase = new SealVaultOprfUseCase(crypto, gateway, store);

    await useCase.execute(validRequest);
    expect(store.saved).toBeNull();
  });
});
