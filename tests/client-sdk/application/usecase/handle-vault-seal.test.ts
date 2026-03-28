// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { HandleVaultSealUseCase } from "../../../../packages/client-sdk/src/application/usecase/handle-vault-seal.js";
import type { VaultPepperStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-attempt-store.js";
import type { VaultPepper } from "../../../../packages/client-sdk/src/domain/model/vault-pepper.js";
import type { VaultAttemptCounter } from "../../../../packages/client-sdk/src/domain/model/vault-attempt-counter.js";

function stubPepperStore(): VaultPepperStore & { saved: VaultPepper | null } {
  const store: VaultPepperStore & { saved: VaultPepper | null } = {
    saved: null,
    save: async (pepper) => { store.saved = pepper; },
    findByDevice: async () => store.saved,
    delete: async () => { store.saved = null; },
  };
  return store;
}

function stubAttemptStore(): VaultAttemptStore & { saved: VaultAttemptCounter | null } {
  const store: VaultAttemptStore & { saved: VaultAttemptCounter | null } = {
    saved: null,
    save: async (counter) => { store.saved = counter; },
    findByDevice: async () => store.saved,
    delete: async () => { store.saved = null; },
  };
  return store;
}

describe("HandleVaultSealUseCase", () => {
  let pepperStore: ReturnType<typeof stubPepperStore>;
  let attemptStore: ReturnType<typeof stubAttemptStore>;
  let useCase: HandleVaultSealUseCase;

  beforeEach(() => {
    pepperStore = stubPepperStore();
    attemptStore = stubAttemptStore();
    useCase = new HandleVaultSealUseCase(pepperStore, attemptStore);
  });

  it("generates and stores a pepper", async () => {
    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });

    expect(result.isOk()).toBe(true);
    expect(pepperStore.saved).not.toBeNull();
    expect(pepperStore.saved!.clientId).toBe("client-1");
    expect(pepperStore.saved!.deviceId).toBe("dev-abc123");
  });

  it("returns the pepper in the response", async () => {
    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });

    const response = result.unwrap();
    expect(response.pepper.length).toBe(32);
    expect(response.pepper.some(b => b !== 0)).toBe(true);
  });

  it("returns the device ID", async () => {
    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.unwrap().deviceId).toBe("dev-abc123");
  });

  it("initializes the attempt counter at 0", async () => {
    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });

    expect(attemptStore.saved).not.toBeNull();
    expect(attemptStore.saved!.consecutiveFailures).toBe(0);
    expect(attemptStore.saved!.isWiped).toBe(false);
  });

  it("replaces existing pepper on re-seal", async () => {
    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    const firstPepper = new Uint8Array(pepperStore.saved!.value);

    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    const secondPepper = pepperStore.saved!.value;

    expect(Buffer.from(firstPepper).equals(Buffer.from(secondPepper))).toBe(false);
  });

  it("resets attempt counter on re-seal", async () => {
    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    // Simulate failures
    attemptStore.saved = {
      ...attemptStore.saved!,
      consecutiveFailures: 2,
    } as VaultAttemptCounter;

    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.saved!.consecutiveFailures).toBe(0);
  });
});
