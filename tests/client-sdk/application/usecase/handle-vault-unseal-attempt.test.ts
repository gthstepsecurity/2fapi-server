// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { HandleVaultUnsealAttemptUseCase } from "../../../../packages/client-sdk/src/application/usecase/handle-vault-unseal-attempt.js";
import { VaultPepper } from "../../../../packages/client-sdk/src/domain/model/vault-pepper.js";
import { VaultAttemptCounter } from "../../../../packages/client-sdk/src/domain/model/vault-attempt-counter.js";
import type { VaultPepperStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-attempt-store.js";

function stubPepperStore(pepper: VaultPepper | null = null): VaultPepperStore & { current: VaultPepper | null; deleted: boolean } {
  const store: VaultPepperStore & { current: VaultPepper | null; deleted: boolean } = {
    current: pepper,
    deleted: false,
    save: async (p) => { store.current = p; },
    findByDevice: async () => store.current,
    delete: async () => { store.current = null; store.deleted = true; },
  };
  return store;
}

function stubAttemptStore(counter: VaultAttemptCounter | null = null): VaultAttemptStore & { current: VaultAttemptCounter | null } {
  const store: VaultAttemptStore & { current: VaultAttemptCounter | null } = {
    current: counter,
    save: async (c) => { store.current = c; },
    findByDevice: async () => store.current,
    delete: async () => { store.current = null; },
  };
  return store;
}

const defaultPepper = VaultPepper.restore("client-1", "dev-abc123", new Uint8Array(32).fill(0xBB), false);
const defaultCounter = VaultAttemptCounter.create("client-1", "dev-abc123");

describe("HandleVaultUnsealAttemptUseCase", () => {
  let pepperStore: ReturnType<typeof stubPepperStore>;
  let attemptStore: ReturnType<typeof stubAttemptStore>;
  let useCase: HandleVaultUnsealAttemptUseCase;

  beforeEach(() => {
    pepperStore = stubPepperStore(defaultPepper);
    attemptStore = stubAttemptStore(defaultCounter);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);
  });

  // --- Happy Path ---

  it("returns allowed with pepper when under threshold", async () => {
    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });

    expect(result.isOk()).toBe(true);
    const response = result.unwrap();
    expect(response.status).toBe("allowed");
    if (response.status === "allowed") {
      expect(response.pepper[0]).toBe(0xBB);
      expect(response.attemptsRemaining).toBe(3);
    }
  });

  it("returns remaining attempts after failures", async () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    if (result.unwrap().status === "allowed") {
      expect(result.unwrap().attemptsRemaining).toBe(2);
    }
  });

  // --- Wiped ---

  it("returns wiped when counter is wiped", async () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure(); // wiped
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.unwrap().status).toBe("wiped");
  });

  it("destroys pepper on wipe", async () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(pepperStore.deleted).toBe(true);
  });

  // --- No vault registered ---

  it("returns error when no pepper found (no vault registered)", async () => {
    pepperStore = stubPepperStore(null);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("NO_VAULT_REGISTERED");
  });

  // --- Record failure ---

  it("increments counter on reportFailure", async () => {
    await useCase.reportFailure({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.consecutiveFailures).toBe(1);
  });

  it("triggers wipe on 3rd failure and destroys pepper", async () => {
    // Pre-set counter at 2 failures
    attemptStore = stubAttemptStore(
      VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure().recordFailure()
    );
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    await useCase.reportFailure({ clientId: "client-1", deviceId: "dev-abc123" });

    expect(attemptStore.current!.isWiped).toBe(true);
    expect(pepperStore.deleted).toBe(true);
  });

  // --- Record success ---

  it("resets counter on reportSuccess", async () => {
    attemptStore = stubAttemptStore(
      VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure().recordFailure()
    );
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    await useCase.reportSuccess({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });

  it("does not reset if already wiped", async () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    await useCase.reportSuccess({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.isWiped).toBe(true); // still wiped
  });

  // --- Concurrent safety ---

  it("creates a new counter if none exists on first attempt", async () => {
    attemptStore = stubAttemptStore(null);
    useCase = new HandleVaultUnsealAttemptUseCase(pepperStore, attemptStore);

    const result = await useCase.execute({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.isOk()).toBe(true);
    expect(attemptStore.current).not.toBeNull();
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });
});
