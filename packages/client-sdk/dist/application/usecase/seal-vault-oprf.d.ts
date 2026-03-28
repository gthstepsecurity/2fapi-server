// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { SealVaultRequest, SealVaultResponse, SealVaultError } from "../../domain/port/incoming/seal-vault.js";
/**
 * Seals a vault using the OPRF protocol (Tier 1a).
 * 1. Validate password
 * 2. Server generates OPRF key (client never sees it)
 * 3. Client blinds password → server evaluates → client unblinds → HKDF → vault key
 * 4. AES-256-GCM encrypt(secret || blinding) → localStorage
 */
export declare class SealVaultOprfUseCase {
    private readonly crypto;
    private readonly oprfGateway;
    private readonly localStore;
    constructor(crypto: CryptoEngine, oprfGateway: OprfGateway, localStore: VaultLocalStore);
    execute(request: SealVaultRequest): Promise<Result<SealVaultResponse, SealVaultError>>;
}
//# sourceMappingURL=seal-vault-oprf.d.ts.map
