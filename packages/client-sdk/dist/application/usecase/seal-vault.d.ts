// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { VaultServerGateway } from "../../domain/port/outgoing/vault-server-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { SealVault, SealVaultRequest, SealVaultResponse, SealVaultError } from "../../domain/port/incoming/seal-vault.js";
export declare class SealVaultUseCase implements SealVault {
    private readonly crypto;
    private readonly server;
    private readonly localStore;
    constructor(crypto: CryptoEngine, server: VaultServerGateway, localStore: VaultLocalStore);
    execute(request: SealVaultRequest): Promise<Result<SealVaultResponse, SealVaultError>>;
}
//# sourceMappingURL=seal-vault.d.ts.map
