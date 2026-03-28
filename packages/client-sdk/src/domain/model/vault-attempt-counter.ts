// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const DEFAULT_THRESHOLD = 3;
const MIN_THRESHOLD = 3;

/**
 * Immutable value object tracking vault unseal attempts per device.
 * Lives server-side — the client cannot modify this.
 *
 * Wipe is permanent: once wiped, the pepper is destroyed and the vault
 * can never be unsealed again (the device must re-enroll).
 */
export class VaultAttemptCounter {
  private constructor(
    readonly clientId: string,
    readonly deviceId: string,
    readonly consecutiveFailures: number,
    readonly isWiped: boolean,
    readonly threshold: number,
  ) {}

  static create(
    clientId: string,
    deviceId: string,
    threshold: number = DEFAULT_THRESHOLD,
  ): VaultAttemptCounter {
    const effectiveThreshold = normalizeThreshold(threshold);
    return new VaultAttemptCounter(clientId, deviceId, 0, false, effectiveThreshold);
  }

  static restore(
    clientId: string,
    deviceId: string,
    consecutiveFailures: number,
    isWiped: boolean,
    threshold: number,
  ): VaultAttemptCounter {
    return new VaultAttemptCounter(clientId, deviceId, consecutiveFailures, isWiped, threshold);
  }

  get attemptsRemaining(): number {
    if (this.isWiped || this.threshold === 0) return 0;
    return Math.max(0, this.threshold - this.consecutiveFailures);
  }

  recordFailure(): VaultAttemptCounter {
    if (this.isWiped) return this;

    const newCount = this.consecutiveFailures + 1;
    const wiped = this.threshold > 0 && newCount >= this.threshold;

    return new VaultAttemptCounter(
      this.clientId,
      this.deviceId,
      newCount,
      wiped,
      this.threshold,
    );
  }

  recordSuccess(): VaultAttemptCounter {
    if (this.isWiped) return this; // wipe is permanent
    return new VaultAttemptCounter(this.clientId, this.deviceId, 0, false, this.threshold);
  }
}

function normalizeThreshold(threshold: number): number {
  if (threshold === 0) return 0; // disabled
  return Math.max(MIN_THRESHOLD, threshold);
}
