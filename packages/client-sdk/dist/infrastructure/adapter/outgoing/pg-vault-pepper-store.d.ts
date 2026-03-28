// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultPepperStore } from "../../../domain/port/outgoing/vault-pepper-store.js";
import { VaultPepper } from "../../../domain/model/vault-pepper.js";
/**
 * Minimal database client interface (subset of pg.Pool).
 */
export interface DatabaseClient {
    query(text: string, values?: unknown[]): Promise<{
        rows: unknown[];
        rowCount: number | null;
    }>;
}
/**
 * PostgreSQL implementation of VaultPepperStore.
 * Stores vault peppers server-side per (client_id, device_id).
 */
export declare class PgVaultPepperStore implements VaultPepperStore {
    private readonly db;
    constructor(db: DatabaseClient);
    save(pepper: VaultPepper): Promise<void>;
    findByDevice(clientId: string, deviceId: string): Promise<VaultPepper | null>;
    delete(clientId: string, deviceId: string): Promise<void>;
}
//# sourceMappingURL=pg-vault-pepper-store.d.ts.map
