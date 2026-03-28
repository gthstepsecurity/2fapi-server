// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Immutable value object representing a server-side vault pepper.
 * The pepper is a random 256-bit value that is:
 * - Generated during vault seal
 * - Stored only on the server (per client_id + device_id)
 * - Delivered to the SDK only during a validated unseal attempt
 * - Permanently destroyed on wipe (making the vault undecryptable)
 */
export declare class VaultPepper {
    readonly clientId: string;
    readonly deviceId: string;
    readonly value: Uint8Array;
    readonly isDestroyed: boolean;
    private constructor();
    static generate(clientId: string, deviceId: string): VaultPepper;
    static restore(clientId: string, deviceId: string, value: Uint8Array, isDestroyed: boolean): VaultPepper;
    /**
     * Returns the pepper value for use in key derivation.
     * Throws if the pepper has been destroyed (wipe scenario).
     */
    valueForDerivation(): Uint8Array;
    /**
     * Destroy the pepper permanently. Returns a new instance with zeroed value.
     * This is irreversible — the vault becomes permanently undecryptable.
     */
    destroy(): VaultPepper;
}
//# sourceMappingURL=vault-pepper.d.ts.map
