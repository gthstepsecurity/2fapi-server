// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { UnsealVaultOprf3FactorUseCase } from "../../../../packages/client-sdk/src/application/usecase/unseal-vault-oprf-3factor.js";
import { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";
import type { CryptoEngine } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../../../packages/client-sdk/src/domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-local-store.js";
import type { HardwareKeyStore, HardwareKeyResult } from "../../../../packages/client-sdk/src/domain/port/outgoing/hardware-key-store.js";

const secret = new Uint8Array(32).fill(0x11);
const blinding = new Uint8Array(32).fill(0x22);
const pt = new Uint8Array(64); pt.set(secret, 0); pt.set(blinding, 32);

function stubCrypto(): CryptoEngine {
  return {
    deriveCredential: async () => ({ secret, blinding }),
    computeCommitment: () => new Uint8Array(32),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32),
    encrypt: async () => ({ iv: new Uint8Array(12), ciphertext: new Uint8Array(64), tag: new Uint8Array(16) }),
    decrypt: async () => new Uint8Array(pt),
    zeroize: (b) => b.fill(0),
    oprfBlind: () => ({ blindedPoint: new Uint8Array(32).fill(0xBB), blindingFactor: new Uint8Array(32).fill(0xCC) }),
    oprfUnblind: () => new Uint8Array(32).fill(0xDD),
    deriveVaultKeyFromOprf: async () => new Uint8Array(32).fill(0xAA),
  };
}

function stubGateway(): OprfGateway {
  return {
    requestEvaluation: async () => ({ status: "allowed" as const, evaluated: new Uint8Array(32).fill(0xEE), attemptsRemaining: 3 }),
    reportFailure: async () => {},
  };
}

function stubStore(entry: VaultEntry | null = null): VaultLocalStore & { deleted: boolean } {
  const s: VaultLocalStore & { deleted: boolean } = {
    deleted: false, save: () => {}, load: () => entry,
    delete: () => { s.deleted = true; }, exists: () => entry !== null,
  };
  return s;
}

function makeEntry(): VaultEntry {
  return VaultEntry.create({
    iv: new Uint8Array(12), ciphertext: new Uint8Array(64), tag: new Uint8Array(16),
    deviceId: "dev-1", createdAtMs: Date.now(), maxTtlHours: 72, version: 2,
  });
}

function stubHwStore(overrides: Partial<HardwareKeyStore> = {}): HardwareKeyStore {
  return {
    isPrfSupported: async () => true,
    deriveKey: async () => ({ status: "ok" as const, hwKey: new Uint8Array(32).fill(0xFF) }),
    ...overrides,
  };
}

const req = { password: "MyD3v!ceP@ss", email: "a@a.com", tenantId: "t1", clientId: "c1", rpId: "acme.com" };

describe("UnsealVaultOprf3FactorUseCase", () => {
  it("unseals with 3 factors: password + OPRF + hardware", async () => {
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), stubGateway(), stubStore(makeEntry()), stubHwStore());
    const result = await uc.execute(req);
    expect(result.isOk()).toBe(true);
    expect(result.unwrap().secret.secret[0]).toBe(0x11);
  });

  it("falls back to 2-factor when PRF not supported", async () => {
    const hw = stubHwStore({ isPrfSupported: async () => false });
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), stubGateway(), stubStore(makeEntry()), hw);
    const result = await uc.execute(req);
    expect(result.isOk()).toBe(true);
  });

  it("falls back to 2-factor when PRF cancelled by user", async () => {
    const hw = stubHwStore({ deriveKey: async () => ({ status: "cancelled" }) });
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), stubGateway(), stubStore(makeEntry()), hw);
    const result = await uc.execute(req);
    expect(result.isOk()).toBe(true); // 2-factor fallback works
  });

  it("combines OPRF output and hardware key in IKM", async () => {
    let capturedIkm: Uint8Array | null = null;
    const crypto = stubCrypto();
    crypto.deriveVaultKeyFromOprf = async (ikm) => { capturedIkm = new Uint8Array(ikm); return new Uint8Array(32).fill(0xAA); };
    const uc = new UnsealVaultOprf3FactorUseCase(crypto, stubGateway(), stubStore(makeEntry()), stubHwStore());

    await uc.execute(req);
    expect(capturedIkm!.length).toBe(64); // OPRF (32) + HW key (32)
    expect(capturedIkm![0]).toBe(0xDD);  // OPRF output
    expect(capturedIkm![32]).toBe(0xFF); // HW key
  });

  it("2-factor IKM is 32 bytes (OPRF only, no HW)", async () => {
    let capturedIkm: Uint8Array | null = null;
    const crypto = stubCrypto();
    crypto.deriveVaultKeyFromOprf = async (ikm) => { capturedIkm = new Uint8Array(ikm); return new Uint8Array(32).fill(0xAA); };
    const hw = stubHwStore({ isPrfSupported: async () => false });
    const uc = new UnsealVaultOprf3FactorUseCase(crypto, stubGateway(), stubStore(makeEntry()), hw);

    await uc.execute(req);
    expect(capturedIkm!.length).toBe(32); // OPRF only
  });

  it("returns VAULT_WIPED when server reports wiped", async () => {
    const gw = stubGateway();
    gw.requestEvaluation = async () => ({ status: "wiped" });
    const store = stubStore(makeEntry());
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), gw, store, stubHwStore());
    const result = await uc.execute(req);
    expect(result.unwrapErr()).toBe("VAULT_WIPED");
    expect(store.deleted).toBe(true);
  });

  it("returns SERVER_UNREACHABLE when OPRF fails", async () => {
    const gw = stubGateway();
    gw.requestEvaluation = async () => { throw new Error("net"); };
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), gw, stubStore(makeEntry()), stubHwStore());
    const result = await uc.execute(req);
    expect(result.unwrapErr()).toBe("SERVER_UNREACHABLE");
  });

  it("zeroizes IKM after key derivation (3-factor)", async () => {
    let ikmRef: Uint8Array | null = null;
    const crypto = stubCrypto();
    const origDerive = crypto.deriveVaultKeyFromOprf;
    crypto.deriveVaultKeyFromOprf = async (ikm, did) => { ikmRef = ikm; return origDerive(ikm, did); };
    const uc = new UnsealVaultOprf3FactorUseCase(crypto, stubGateway(), stubStore(makeEntry()), stubHwStore());

    await uc.execute(req);
    expect(ikmRef!.every(b => b === 0)).toBe(true);
  });

  it("device cloned → hardware key not portable (different TPM)", async () => {
    // Simulates: device clone, hardware deriveKey fails
    const hw = stubHwStore({ deriveKey: async () => ({ status: "error", message: "TPM not found" }) });
    const uc = new UnsealVaultOprf3FactorUseCase(stubCrypto(), stubGateway(), stubStore(makeEntry()), hw);
    // Falls back to 2-factor
    const result = await uc.execute(req);
    expect(result.isOk()).toBe(true); // 2-factor still works
  });
});
