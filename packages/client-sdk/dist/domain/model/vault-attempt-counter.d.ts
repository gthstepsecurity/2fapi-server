// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Immutable value object tracking vault unseal attempts per device.
 * Lives server-side — the client cannot modify this.
 *
 * Wipe is permanent: once wiped, the pepper is destroyed and the vault
 * can never be unsealed again (the device must re-enroll).
 */
export declare class VaultAttemptCounter {
    readonly clientId: string;
    readonly deviceId: string;
    readonly consecutiveFailures: number;
    readonly isWiped: boolean;
    readonly threshold: number;
    private constructor();
    static create(clientId: string, deviceId: string, threshold?: number): VaultAttemptCounter;
    static restore(clientId: string, deviceId: string, consecutiveFailures: number, isWiped: boolean, threshold: number): VaultAttemptCounter;
    get attemptsRemaining(): number;
    recordFailure(): VaultAttemptCounter;
    recordSuccess(): VaultAttemptCounter;
}
//# sourceMappingURL=vault-attempt-counter.d.ts.map
