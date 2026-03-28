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
export type ActiveTier =
  | { readonly tier: 2; readonly credentialId: string }
  | { readonly tier: 1; readonly deviceId: string }
  | { readonly tier: 0 };

export class TierDetector {
  constructor(
    private readonly localStore: VaultLocalStore,
    private readonly biometricAvailable: (email: string) => Promise<boolean>,
  ) {}

  async detect(email: string, deviceContext: DeviceContext): Promise<ActiveTier> {
    // Shared device → always Tier 0
    if (deviceContext.isShared) {
      return { tier: 0 };
    }

    // Check biometric (Tier 2)
    try {
      const hasBiometric = await this.biometricAvailable(email);
      if (hasBiometric) {
        return { tier: 2, credentialId: `bio-${email}` };
      }
    } catch {
      // Biometric check failed — fall through
    }

    // Check vault (Tier 1)
    if (this.localStore.exists(email)) {
      const entry = this.localStore.load(email);
      if (entry && !entry.isExpired(Date.now())) {
        return { tier: 1, deviceId: entry.deviceId };
      }
    }

    // Default: Tier 0
    return { tier: 0 };
  }
}
