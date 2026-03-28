// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultAttemptStore } from "../../../domain/port/outgoing/vault-attempt-store.js";
import { VaultAttemptCounter } from "../../../domain/model/vault-attempt-counter.js";
export interface DatabaseClient {
    query(text: string, values?: unknown[]): Promise<{
        rows: unknown[];
        rowCount: number | null;
    }>;
}
/**
 * PostgreSQL implementation of VaultAttemptStore.
 * Uses UPSERT for atomic create/update of attempt counters.
 */
export declare class PgVaultAttemptStore implements VaultAttemptStore {
    private readonly db;
    constructor(db: DatabaseClient);
    findByDevice(clientId: string, deviceId: string): Promise<VaultAttemptCounter | null>;
    save(counter: VaultAttemptCounter): Promise<void>;
    delete(clientId: string, deviceId: string): Promise<void>;
}
//# sourceMappingURL=pg-vault-attempt-store.d.ts.map
