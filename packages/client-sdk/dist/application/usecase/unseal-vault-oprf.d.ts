// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { UnsealVaultRequest, UnsealVaultResponse, UnsealVaultError, UnsealVaultFailureDetail } from "../../domain/port/incoming/unseal-vault.js";
/**
 * Unseals a vault using the OPRF protocol (Tier 1a — 2-factor: password + server OPRF).
 * The server never sees the password. The client never sees the OPRF key.
 */
export declare class UnsealVaultOprfUseCase {
    private readonly crypto;
    private readonly oprfGateway;
    private readonly localStore;
    /** Detail of the last error (available after a failed execute call). */
    lastErrorDetail: UnsealVaultFailureDetail | null;
    constructor(crypto: CryptoEngine, oprfGateway: OprfGateway, localStore: VaultLocalStore);
    execute(request: UnsealVaultRequest): Promise<Result<UnsealVaultResponse, UnsealVaultError>>;
}
//# sourceMappingURL=unseal-vault-oprf.d.ts.map
