// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultLocalStore } from "../port/outgoing/vault-local-store.js";
import type { DeviceContext } from "../model/device-context.js";
/**
 * Domain service: detects the active storage tier for a given email on this device.
 *
 * Tier cascade (highest comfort first):
 *   Tier 2: biometric credential exists → transparent login
 *   Tier 1: vault exists in localStorage → password login
 *   Tier 0: nothing stored → passphrase/PIN entry
 */
export type ActiveTier = {
    readonly tier: 2;
    readonly credentialId: string;
} | {
    readonly tier: 1;
    readonly deviceId: string;
} | {
    readonly tier: 0;
};
export declare class TierDetector {
    private readonly localStore;
    private readonly biometricAvailable;
    constructor(localStore: VaultLocalStore, biometricAvailable: (email: string) => Promise<boolean>);
    detect(email: string, deviceContext: DeviceContext): Promise<ActiveTier>;
}
//# sourceMappingURL=tier-detector.d.ts.map
