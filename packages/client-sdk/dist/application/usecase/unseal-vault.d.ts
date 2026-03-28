// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { VaultServerGateway } from "../../domain/port/outgoing/vault-server-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { UnsealVault, UnsealVaultRequest, UnsealVaultResponse, UnsealVaultError } from "../../domain/port/incoming/unseal-vault.js";
export declare class UnsealVaultUseCase implements UnsealVault {
    private readonly crypto;
    private readonly server;
    private readonly localStore;
    constructor(crypto: CryptoEngine, server: VaultServerGateway, localStore: VaultLocalStore);
    execute(request: UnsealVaultRequest): Promise<Result<UnsealVaultResponse, UnsealVaultError>>;
}
//# sourceMappingURL=unseal-vault.d.ts.map
