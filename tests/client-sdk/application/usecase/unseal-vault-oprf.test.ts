// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { UnsealVaultOprfUseCase } from "../../../../packages/client-sdk/src/application/usecase/unseal-vault-oprf.js";
import type { CryptoEngine, EncryptedPayload } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { OprfGateway, OprfEvaluationResponse } from "../../../../packages/client-sdk/src/domain/port/outgoing/oprf-gateway.js";
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
    deviceId: overrides.deviceId ?? "dev-abc123",
    createdAtMs: overrides.createdAtMs ?? Date.now(),
    maxTtlHours: overrides.maxTtlHours ?? 72,
    version: 2,
  });
}

const secret = new Uint8Array(32).fill(0x11);
const blinding = new Uint8Array(32).fill(0x22);
const plaintext = new Uint8Array(64);
plaintext.set(secret, 0);
plaintext.set(blinding, 32);

function stubCrypto(overrides: Partial<CryptoEngine> = {}): CryptoEngine {
  return {
    deriveCredential: async () => ({ secret, blinding }),
    computeCommitment: () => new Uint8Array(32),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32).fill(0xAA),
    encrypt: async () => ({ iv: new Uint8Array(12), ciphertext: new Uint8Array(64), tag: new Uint8Array(16) }),
    decrypt: async () => new Uint8Array(plaintext),
    zeroize: (buf) => buf.fill(0),
    oprfBlind: (password) => ({
      blindedPoint: new Uint8Array(32).fill(0xBB),
      blindingFactor: new Uint8Array(32).fill(0xCC),
    }),
    oprfUnblind: (evaluated, blindingFactor) => new Uint8Array(32).fill(0xDD),
    deriveVaultKeyFromOprf: async (oprfOutput, deviceId) => new Uint8Array(32).fill(0xAA),
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
  email: "bob@acme.com",
  tenantId: "tenant-1",
  clientId: "client-bob",
};

describe("UnsealVaultOprfUseCase", () => {
  let crypto: CryptoEngine;
  let oprfGateway: OprfGateway;
  let localStore: ReturnType<typeof stubStore>;
  let useCase: UnsealVaultOprfUseCase;

  beforeEach(() => {
    crypto = stubCrypto();
    oprfGateway = stubOprfGateway();
    localStore = stubStore(makeVaultEntry());
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);
  });

  // --- Test 1 ---
  it("returns NO_VAULT_FOUND when store is empty", async () => {
    localStore = stubStore(null);
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("NO_VAULT_FOUND");
  });

  // --- Test 2 ---
  it("returns VAULT_EXPIRED and deletes entry when TTL exceeded", async () => {
    const expiredEntry = makeVaultEntry({ createdAtMs: Date.now() - 73 * 60 * 60 * 1000 });
    localStore = stubStore(expiredEntry);
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("VAULT_EXPIRED");
    expect(localStore.deleted).toBe(true);
  });

  // --- Test 3 ---
  it("calls OPRF gateway with blinded password", async () => {
    let evaluationCalled = false;
    let capturedBlinded: Uint8Array | null = null;
    oprfGateway = stubOprfGateway({
      requestEvaluation: async (params) => {
        evaluationCalled = true;
        capturedBlinded = params.blindedPoint;
        return { status: "allowed", evaluated: new Uint8Array(32).fill(0xEE), attemptsRemaining: 3 };
      },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    await useCase.execute(validRequest);
    expect(evaluationCalled).toBe(true);
    expect(capturedBlinded).not.toBeNull();
    expect(capturedBlinded!.length).toBe(32);
  });

  // --- Test 4 ---
  it("returns VAULT_WIPED and deletes entry when server reports wiped", async () => {
    oprfGateway = stubOprfGateway({
      requestEvaluation: async () => ({ status: "wiped" }),
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("VAULT_WIPED");
    expect(localStore.deleted).toBe(true);
  });

  // --- Test 5 ---
  it("derives vault key from OPRF output via unblind + HKDF", async () => {
    let unblindCalled = false;
    let deriveKeyCalledWithOprfOutput: Uint8Array | null = null;

    crypto = stubCrypto({
      oprfUnblind: (evaluated, blindingFactor) => {
        unblindCalled = true;
        return new Uint8Array(32).fill(0xDD);
      },
      deriveVaultKeyFromOprf: async (oprfOutput, deviceId) => {
        deriveKeyCalledWithOprfOutput = new Uint8Array(oprfOutput);
        return new Uint8Array(32).fill(0xAA);
      },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    await useCase.execute(validRequest);
    expect(unblindCalled).toBe(true);
    expect(deriveKeyCalledWithOprfOutput).not.toBeNull();
    expect(deriveKeyCalledWithOprfOutput![0]).toBe(0xDD);
  });

  // --- Test 6 ---
  it("decrypts vault and returns secret with attemptsRemaining", async () => {
    const result = await useCase.execute(validRequest);
    expect(result.isOk()).toBe(true);
    const response = result.unwrap();
    expect(response.secret.secret[0]).toBe(0x11);
    expect(response.secret.blinding[0]).toBe(0x22);
    expect(response.attemptsRemaining).toBe(3);
  });

  // --- Test 7 ---
  it("zeroizes OPRF output, vault key, and plaintext after use", async () => {
    let oprfOutputRef: Uint8Array | null = null;
    let vaultKeyRef: Uint8Array | null = null;
    let plaintextRef: Uint8Array | null = null;

    crypto = stubCrypto({
      oprfUnblind: (evaluated, bf) => {
        const u = new Uint8Array(32).fill(0xDD);
        oprfOutputRef = u;
        return u;
      },
      deriveVaultKeyFromOprf: async (oprfOutput) => {
        const key = new Uint8Array(32).fill(0xAA);
        vaultKeyRef = key;
        return key;
      },
      decrypt: async () => {
        const pt = new Uint8Array(plaintext);
        plaintextRef = pt;
        return pt;
      },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    await useCase.execute(validRequest);

    expect(oprfOutputRef).not.toBeNull();
    expect(oprfOutputRef!.every(b => b === 0)).toBe(true);
    expect(vaultKeyRef).not.toBeNull();
    expect(vaultKeyRef!.every(b => b === 0)).toBe(true);
    expect(plaintextRef).not.toBeNull();
    expect(plaintextRef!.every(b => b === 0)).toBe(true);
  });

  // --- Iteration 02: Wrong password detection ---

  it("returns WRONG_PASSWORD when GCM decryption fails (wrong password)", async () => {
    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("WRONG_PASSWORD");
  });

  it("reports failure to server when password is wrong", async () => {
    let failureReported = false;
    let reportedClientId = "";
    let reportedDeviceId = "";

    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    oprfGateway = stubOprfGateway({
      reportFailure: async (clientId, deviceId) => {
        failureReported = true;
        reportedClientId = clientId;
        reportedDeviceId = deviceId;
      },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    await useCase.execute(validRequest);
    expect(failureReported).toBe(true);
    expect(reportedClientId).toBe("client-bob");
    expect(reportedDeviceId).toBe("dev-abc123");
  });

  it("wrong password error includes attempts remaining from OPRF response", async () => {
    crypto = stubCrypto({
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    oprfGateway = stubOprfGateway({
      requestEvaluation: async () => ({
        status: "allowed" as const,
        evaluated: new Uint8Array(32).fill(0xEE),
        attemptsRemaining: 2,
      }),
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("WRONG_PASSWORD");
    // The error must carry attemptsRemaining so the UI can display it
    expect((result as any).error).toBe("WRONG_PASSWORD");
    // We need attemptsRemaining accessible — test the enriched error detail
    const detail = useCase.lastErrorDetail;
    expect(detail).not.toBeNull();
    expect(detail!.attemptsRemaining).toBe(2);
  });

  it("zeroizes vault key and OPRF output even when password is wrong", async () => {
    let oprfOutputRef: Uint8Array | null = null;
    let vaultKeyRef: Uint8Array | null = null;

    crypto = stubCrypto({
      oprfUnblind: () => {
        const u = new Uint8Array(32).fill(0xDD);
        oprfOutputRef = u;
        return u;
      },
      deriveVaultKeyFromOprf: async () => {
        const key = new Uint8Array(32).fill(0xAA);
        vaultKeyRef = key;
        return key;
      },
      decrypt: async () => { throw new Error("GCM authentication failed"); },
    });
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    await useCase.execute(validRequest);

    expect(oprfOutputRef!.every(b => b === 0)).toBe(true);
    expect(vaultKeyRef!.every(b => b === 0)).toBe(true);
  });

  // --- Iteration 03: Three failures → OPRF key destroyed ---

  it("three failures destroy OPRF key and refuse further evaluation", async () => {
    // This is an integration test across HandleOprfEvaluate
    const { HandleOprfEvaluateUseCase } = await import(
      "../../../../packages/client-sdk/src/application/usecase/handle-oprf-evaluate.js"
    );
    const { OprfKey } = await import(
      "../../../../packages/client-sdk/src/domain/model/oprf-key.js"
    );
    const { VaultAttemptCounter } = await import(
      "../../../../packages/client-sdk/src/domain/model/vault-attempt-counter.js"
    );

    const keyMap = new Map<string, any>();
    const counterMap = new Map<string, any>();

    const keyStore = {
      save: async (k: any) => keyMap.set(`${k.clientId}:${k.deviceId}`, k),
      findByDevice: async (c: string, d: string) => keyMap.get(`${c}:${d}`) ?? null,
      delete: async (c: string, d: string) => keyMap.delete(`${c}:${d}`),
    };
    const attemptStore = {
      save: async (c: any) => counterMap.set(`${c.clientId}:${c.deviceId}`, c),
      findByDevice: async (c: string, d: string) => counterMap.get(`${c}:${d}`) ?? null,
      delete: async (c: string, d: string) => counterMap.delete(`${c}:${d}`),
    };

    const serverUseCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    // Seal: generate OPRF key
    await serverUseCase.seal({ clientId: "alice", deviceId: "dev-1" });
    expect(keyMap.has("alice:dev-1")).toBe(true);

    // 3 failures
    await serverUseCase.reportFailure({ clientId: "alice", deviceId: "dev-1" });
    await serverUseCase.reportFailure({ clientId: "alice", deviceId: "dev-1" });
    await serverUseCase.reportFailure({ clientId: "alice", deviceId: "dev-1" });

    // Key destroyed
    expect(keyMap.has("alice:dev-1")).toBe(false);

    // Evaluate after wipe → refused
    const result = await serverUseCase.evaluate({
      clientId: "alice",
      deviceId: "dev-1",
      blindedPoint: new Uint8Array(32).fill(0xAA),
    });
    expect(result.unwrap().status).toBe("wiped");
  });

  it("client deletes local vault when server reports wiped after 3rd failure", async () => {
    oprfGateway = stubOprfGateway({
      requestEvaluation: async () => ({ status: "wiped" }),
    });
    localStore = stubStore(makeVaultEntry());
    useCase = new UnsealVaultOprfUseCase(crypto, oprfGateway, localStore);

    const result = await useCase.execute(validRequest);
    expect(result.unwrapErr()).toBe("VAULT_WIPED");
    expect(localStore.deleted).toBe(true);
  });

  it("correct password after wipe still cannot unseal — permanence proven", async () => {
    // Server-side: key destroyed, counter wiped
    const { HandleOprfEvaluateUseCase } = await import(
      "../../../../packages/client-sdk/src/application/usecase/handle-oprf-evaluate.js"
    );

    const keyMap = new Map<string, any>();
    const counterMap = new Map<string, any>();
    const keyStore = {
      save: async (k: any) => keyMap.set(`${k.clientId}:${k.deviceId}`, k),
      findByDevice: async (c: string, d: string) => keyMap.get(`${c}:${d}`) ?? null,
      delete: async (c: string, d: string) => keyMap.delete(`${c}:${d}`),
    };
    const attemptStore = {
      save: async (c: any) => counterMap.set(`${c.clientId}:${c.deviceId}`, c),
      findByDevice: async (c: string, d: string) => counterMap.get(`${c}:${d}`) ?? null,
      delete: async (c: string, d: string) => counterMap.delete(`${c}:${d}`),
    };

    const serverUseCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);
    await serverUseCase.seal({ clientId: "alice", deviceId: "dev-1" });

    // Wipe
    for (let i = 0; i < 3; i++) {
      await serverUseCase.reportFailure({ clientId: "alice", deviceId: "dev-1" });
    }

    // Even with "correct" blinded point, evaluation is permanently refused
    const attempt1 = await serverUseCase.evaluate({
      clientId: "alice", deviceId: "dev-1",
      blindedPoint: new Uint8Array(32).fill(0xAA),
    });
    expect(attempt1.unwrap().status).toBe("wiped");

    // Re-seal is blocked (key store empty, counter still wiped)
    const attempt2 = await serverUseCase.evaluate({
      clientId: "alice", deviceId: "dev-1",
      blindedPoint: new Uint8Array(32).fill(0xBB),
    });
    expect(attempt2.unwrap().status).toBe("wiped");
  });
});
