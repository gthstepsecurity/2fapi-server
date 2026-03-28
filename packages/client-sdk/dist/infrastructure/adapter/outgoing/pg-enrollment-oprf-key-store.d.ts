// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { EnrollmentOprfKeyStore } from "../../../domain/port/outgoing/enrollment-oprf-key-store.js";
export interface DatabaseClient {
    query(text: string, values?: unknown[]): Promise<{
        rows: unknown[];
        rowCount: number | null;
    }>;
}
/**
 * PostgreSQL adapter for enrollment OPRF key storage (R15-02).
 * Per-user keys — limits blast radius of a breach to a single user.
 */
export declare class PgEnrollmentOprfKeyStore implements EnrollmentOprfKeyStore {
    private readonly db;
    constructor(db: DatabaseClient);
    generate(tenantId: string, clientId: string): Promise<void>;
    exists(tenantId: string, clientId: string): Promise<boolean>;
    evaluate(tenantId: string, clientId: string, blindedPoint: Uint8Array): Promise<Uint8Array>;
    delete(tenantId: string, clientId: string): Promise<void>;
}
//# sourceMappingURL=pg-enrollment-oprf-key-store.d.ts.map
