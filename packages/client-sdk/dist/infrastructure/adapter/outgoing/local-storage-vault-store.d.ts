// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultLocalStore } from "../../../domain/port/outgoing/vault-local-store.js";
import { VaultEntry } from "../../../domain/model/vault-entry.js";
/**
 * Infrastructure adapter: stores encrypted vault entries in localStorage.
 * Implements the VaultLocalStore driven port.
 */
export declare class LocalStorageVaultStore implements VaultLocalStore {
    private readonly storage;
    constructor(storage: Storage);
    save(email: string, entry: VaultEntry): void;
    load(email: string): VaultEntry | null;
    delete(email: string): void;
    exists(email: string): boolean;
}
//# sourceMappingURL=local-storage-vault-store.d.ts.map
