// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";

const PEPPER_LENGTH = 32;

/**
 * Immutable value object representing a server-side vault pepper.
 * The pepper is a random 256-bit value that is:
 * - Generated during vault seal
 * - Stored only on the server (per client_id + device_id)
 * - Delivered to the SDK only during a validated unseal attempt
 * - Permanently destroyed on wipe (making the vault undecryptable)
 */
export class VaultPepper {
  private constructor(
    readonly clientId: string,
    readonly deviceId: string,
    readonly value: Uint8Array,
    readonly isDestroyed: boolean,
  ) {}

  static generate(clientId: string, deviceId: string): VaultPepper {
    const bytes = new Uint8Array(randomBytes(PEPPER_LENGTH));
    return new VaultPepper(clientId, deviceId, bytes, false);
  }

  static restore(
    clientId: string,
    deviceId: string,
    value: Uint8Array,
    isDestroyed: boolean,
  ): VaultPepper {
    return new VaultPepper(clientId, deviceId, value, isDestroyed);
  }

  /**
   * Returns the pepper value for use in key derivation.
   * Throws if the pepper has been destroyed (wipe scenario).
   */
  valueForDerivation(): Uint8Array {
    if (this.isDestroyed) {
      throw new Error("Pepper has been destroyed");
    }
    return this.value;
  }

  /**
   * Destroy the pepper permanently. Returns a new instance with zeroed value.
   * This is irreversible — the vault becomes permanently undecryptable.
   */
  destroy(): VaultPepper {
    const zeroed = new Uint8Array(PEPPER_LENGTH);
    return new VaultPepper(this.clientId, this.deviceId, zeroed, true);
  }
}
