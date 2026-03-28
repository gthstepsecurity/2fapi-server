// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import { VaultAttemptCounter } from "../../domain/model/vault-attempt-counter.js";
import type { VaultPepperStore } from "../../domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";

interface DeviceIdentifier {
  readonly clientId: string;
  readonly deviceId: string;
}

export type HandleUnsealResponse =
  | { readonly status: "allowed"; readonly pepper: Uint8Array; readonly attemptsRemaining: number }
  | { readonly status: "wiped" };

/**
 * Server-side use case: validate an unseal attempt and deliver the pepper.
 * - Checks the attempt counter
 * - If under threshold: delivers the pepper
 * - If wiped: destroys the pepper permanently and returns "wiped"
 */
export class HandleVaultUnsealAttemptUseCase {
  constructor(
    private readonly pepperStore: VaultPepperStore,
    private readonly attemptStore: VaultAttemptStore,
  ) {}

  async execute(params: DeviceIdentifier): Promise<Result<HandleUnsealResponse, string>> {
    // 1. Check attempt counter first (wipe state persists even after pepper destruction)
    const counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
    if (counter?.isWiped) {
      // Ensure pepper is destroyed (idempotent)
      await this.pepperStore.delete(params.clientId, params.deviceId);
      return ok({ status: "wiped" });
    }

    // 2. Check pepper exists
    const pepper = await this.pepperStore.findByDevice(params.clientId, params.deviceId);
    if (!pepper) {
      return err("NO_VAULT_REGISTERED");
    }

    // 3. Create counter if first attempt
    if (!counter) {
      const newCounter = VaultAttemptCounter.create(params.clientId, params.deviceId);
      await this.attemptStore.save(newCounter);
      return ok({
        status: "allowed",
        pepper: pepper.valueForDerivation(),
        attemptsRemaining: newCounter.attemptsRemaining,
      });
    }

    // 4. Deliver pepper
    return ok({
      status: "allowed",
      pepper: pepper.valueForDerivation(),
      attemptsRemaining: counter.attemptsRemaining,
    });
  }

  async reportFailure(params: DeviceIdentifier): Promise<void> {
    let counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
    if (!counter) {
      counter = VaultAttemptCounter.create(params.clientId, params.deviceId);
    }

    const updated = counter.recordFailure();
    await this.attemptStore.save(updated);

    // Destroy pepper if wipe triggered
    if (updated.isWiped) {
      await this.pepperStore.delete(params.clientId, params.deviceId);
    }
  }

  async reportSuccess(params: DeviceIdentifier): Promise<void> {
    const counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
    if (!counter) return;

    const reset = counter.recordSuccess();
    await this.attemptStore.save(reset);
  }
}
