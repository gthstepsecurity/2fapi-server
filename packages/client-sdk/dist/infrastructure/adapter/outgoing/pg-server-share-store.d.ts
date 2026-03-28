// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface DatabaseClient {
    query(text: string, values?: unknown[]): Promise<{
        rows: unknown[];
        rowCount: number | null;
    }>;
}
/**
 * Server-side share storage port for distributed Sigma proofs (R31).
 */
export interface ServerShareStore {
    save(tenantId: string, clientId: string, shareS: Uint8Array, shareR: Uint8Array, partialCommitment: Uint8Array): Promise<void>;
    findByClient(tenantId: string, clientId: string): Promise<{
        shareS: Uint8Array;
        shareR: Uint8Array;
    } | null>;
    delete(tenantId: string, clientId: string): Promise<void>;
}
/**
 * PostgreSQL adapter for server secret share storage (R31).
 */
export declare class PgServerShareStore implements ServerShareStore {
    private readonly db;
    constructor(db: DatabaseClient);
    save(tenantId: string, clientId: string, shareS: Uint8Array, shareR: Uint8Array, partialCommitment: Uint8Array): Promise<void>;
    findByClient(tenantId: string, clientId: string): Promise<{
        shareS: Uint8Array;
        shareR: Uint8Array;
    } | null>;
    delete(tenantId: string, clientId: string): Promise<void>;
}
//# sourceMappingURL=pg-server-share-store.d.ts.map
