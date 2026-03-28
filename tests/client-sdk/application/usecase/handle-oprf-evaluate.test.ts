// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { HandleOprfEvaluateUseCase } from "../../../../packages/client-sdk/src/application/usecase/handle-oprf-evaluate.js";
import { OprfKey } from "../../../../packages/client-sdk/src/domain/model/oprf-key.js";
import { VaultAttemptCounter } from "../../../../packages/client-sdk/src/domain/model/vault-attempt-counter.js";
import type { OprfKeyStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/oprf-key-store.js";
import type { VaultAttemptStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-attempt-store.js";

// --- Stubs ---

function stubKeyStore(key: OprfKey | null = null): OprfKeyStore & { current: OprfKey | null; deleted: boolean } {
  const store: OprfKeyStore & { current: OprfKey | null; deleted: boolean } = {
    current: key,
    deleted: false,
    save: async (k) => { store.current = k; },
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

// Valid 32-byte blinded point (just non-zero bytes for stub purposes)
const validBlindedPoint = new Uint8Array(32).fill(0xAA);
// Identity point (all zeros except specific encoding)
const identityPoint = new Uint8Array(32).fill(0x00);

const defaultKey = OprfKey.restore("client-1", "dev-abc123", new Uint8Array(32).fill(0xBB), false);
const defaultCounter = VaultAttemptCounter.create("client-1", "dev-abc123");

describe("HandleOprfEvaluateUseCase", () => {
  let keyStore: ReturnType<typeof stubKeyStore>;
  let attemptStore: ReturnType<typeof stubAttemptStore>;
  let useCase: HandleOprfEvaluateUseCase;

  beforeEach(() => {
    keyStore = stubKeyStore(defaultKey);
    attemptStore = stubAttemptStore(defaultCounter);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);
  });

  // --- Scenario #41: Invalid blinded point rejected ---

  it("rejects a zero-length blinded point", async () => {
    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: new Uint8Array(0),
    });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("INVALID_BLINDED_ELEMENT");
  });

  it("rejects a blinded point with wrong length", async () => {
    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: new Uint8Array(16),
    });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("INVALID_BLINDED_ELEMENT");
  });

  it("does not increment counter on invalid blinded point", async () => {
    await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: new Uint8Array(0),
    });
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });

  // --- Scenario #42: OPRF key not found ---

  it("returns error when no OPRF key exists for device", async () => {
    keyStore = stubKeyStore(null);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("NO_VAULT_REGISTERED");
  });

  // --- Scenario #40: Evaluation refused after wipe ---

  it("refuses evaluation when vault is wiped", async () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(result.isOk()).toBe(true);
    expect(result.unwrap().status).toBe("wiped");
  });

  it("destroys OPRF key when wiped", async () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(keyStore.deleted).toBe(true);
  });

  // --- Scenario #37: Counter checked before evaluation ---

  it("returns attempts remaining with evaluation", async () => {
    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(result.isOk()).toBe(true);
    const response = result.unwrap();
    expect(response.status).toBe("allowed");
    if (response.status === "allowed") {
      expect(response.attemptsRemaining).toBe(3);
    }
  });

  it("returns correct attempts after failures", async () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    if (result.unwrap().status === "allowed") {
      expect(result.unwrap().attemptsRemaining).toBe(2);
    }
  });

  // --- Scenario #35: Server generates OPRF key on seal ---

  it("generates and stores OPRF key on seal", async () => {
    keyStore = stubKeyStore(null);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    const result = await useCase.seal({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.isOk()).toBe(true);
    expect(keyStore.current).not.toBeNull();
    expect(keyStore.current!.clientId).toBe("client-1");
  });

  it("seal response indicates ready (no key sent to client)", async () => {
    keyStore = stubKeyStore(null);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    const result = await useCase.seal({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(result.unwrap().status).toBe("ready");
  });

  it("seal resets attempt counter", async () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure().recordFailure();
    attemptStore = stubAttemptStore(counter);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    await useCase.seal({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });

  // --- Scenario #36: Server evaluates blindly ---

  it("returns evaluated point on valid request", async () => {
    const result = await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(result.isOk()).toBe(true);
    const response = result.unwrap();
    expect(response.status).toBe("allowed");
    if (response.status === "allowed") {
      expect(response.evaluated).toBeInstanceOf(Uint8Array);
      expect(response.evaluated.length).toBe(32);
    }
  });

  it("creates counter on first evaluation if none exists", async () => {
    attemptStore = stubAttemptStore(null);
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    await useCase.evaluate({
      clientId: "client-1",
      deviceId: "dev-abc123",
      blindedPoint: validBlindedPoint,
    });
    expect(attemptStore.current).not.toBeNull();
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });

  // --- reportFailure / reportSuccess ---

  it("increments counter on failure report", async () => {
    await useCase.reportFailure({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.consecutiveFailures).toBe(1);
  });

  it("destroys key on 3rd failure (wipe)", async () => {
    attemptStore = stubAttemptStore(
      VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure().recordFailure()
    );
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    await useCase.reportFailure({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.isWiped).toBe(true);
    expect(keyStore.deleted).toBe(true);
  });

  it("resets counter on success report", async () => {
    attemptStore = stubAttemptStore(
      VaultAttemptCounter.create("client-1", "dev-abc123").recordFailure().recordFailure()
    );
    useCase = new HandleOprfEvaluateUseCase(keyStore, attemptStore);

    await useCase.reportSuccess({ clientId: "client-1", deviceId: "dev-abc123" });
    expect(attemptStore.current!.consecutiveFailures).toBe(0);
  });
});
