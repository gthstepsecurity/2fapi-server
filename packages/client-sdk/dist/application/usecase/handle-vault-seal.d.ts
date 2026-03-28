// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { VaultPepperStore } from "../../domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";
interface HandleVaultSealRequest {
    readonly clientId: string;
    readonly deviceId: string;
    readonly threshold?: number;
}
interface HandleVaultSealResponse {
    readonly pepper: Uint8Array;
    readonly deviceId: string;
}
/**
 * Server-side use case: generate a pepper for vault sealing.
 * Stores the pepper and initializes the attempt counter.
 */
export declare class HandleVaultSealUseCase {
    private readonly pepperStore;
    private readonly attemptStore;
    constructor(pepperStore: VaultPepperStore, attemptStore: VaultAttemptStore);
    execute(request: HandleVaultSealRequest): Promise<Result<HandleVaultSealResponse, string>>;
    deleteVault(clientId: string, deviceId: string): Promise<void>;
}
export {};
//# sourceMappingURL=handle-vault-seal.d.ts.map
