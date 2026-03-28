// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { HardwareKeyStore } from "../../domain/port/outgoing/hardware-key-store.js";
import type { UnsealVaultRequest, UnsealVaultResponse, UnsealVaultError } from "../../domain/port/incoming/unseal-vault.js";
/**
 * Unseals a vault using 3 factors: password + OPRF + hardware (Tier 1b).
 * vault_key = HKDF(OPRF_output || hardware_key, device_id)
 *
 * Falls back to 2-factor (Tier 1a) if hardware PRF is unavailable.
 */
export declare class UnsealVaultOprf3FactorUseCase {
    private readonly crypto;
    private readonly oprfGateway;
    private readonly localStore;
    private readonly hardwareKeyStore;
    constructor(crypto: CryptoEngine, oprfGateway: OprfGateway, localStore: VaultLocalStore, hardwareKeyStore: HardwareKeyStore);
    execute(request: UnsealVaultRequest & {
        rpId?: string;
    }): Promise<Result<UnsealVaultResponse, UnsealVaultError>>;
}
//# sourceMappingURL=unseal-vault-oprf-3factor.d.ts.map
