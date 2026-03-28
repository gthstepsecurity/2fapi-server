// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import { VaultPepper } from "../../domain/model/vault-pepper.js";
import { VaultAttemptCounter } from "../../domain/model/vault-attempt-counter.js";
import type { VaultPepperStore } from "../../domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";

interface HandleVaultSealRequest {
  readonly clientId: string;
  readonly deviceId: string;
  readonly threshold?: number;
}

interface HandleVaultSealResponse {
  readonly pepper: Uint8Array;
  readonly deviceId: string;
}

/**
 * Server-side use case: generate a pepper for vault sealing.
 * Stores the pepper and initializes the attempt counter.
 */
export class HandleVaultSealUseCase {
  constructor(
    private readonly pepperStore: VaultPepperStore,
    private readonly attemptStore: VaultAttemptStore,
  ) {}

  async execute(request: HandleVaultSealRequest): Promise<Result<HandleVaultSealResponse, string>> {
    // 1. Generate a fresh random pepper
    const pepper = VaultPepper.generate(request.clientId, request.deviceId);

    // 2. Store pepper (replaces any existing one for this device)
    await this.pepperStore.save(pepper);

    // 3. Initialize (or reset) the attempt counter
    const counter = VaultAttemptCounter.create(
      request.clientId,
      request.deviceId,
      request.threshold,
    );
    await this.attemptStore.save(counter);

    return ok({
      pepper: pepper.valueForDerivation(),
      deviceId: request.deviceId,
    });
  }

  async deleteVault(clientId: string, deviceId: string): Promise<void> {
    await this.pepperStore.delete(clientId, deviceId);
    await this.attemptStore.delete(clientId, deviceId);
  }
}
