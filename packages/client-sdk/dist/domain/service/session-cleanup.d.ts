// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: ensures all traces are removed after a session ends.
 * Critical for shared devices (Tier 0) but applied to all tiers.
 */
export declare class SessionCleanup {
    private readonly zeroize;
    constructor(zeroize: (buffer: Uint8Array) => void);
    /**
     * Execute the full cleanup checklist.
     * Best-effort: continues even if individual steps fail.
     */
    execute(params: CleanupParams): CleanupResult;
}
export interface CleanupParams {
    readonly wasmBuffers: Uint8Array[];
    readonly jsReferences: {
        value: unknown;
    }[];
    readonly sessionStorage?: Storage;
    readonly sessionStorageKeys: string[];
    readonly expireCookie?: () => void;
}
export interface CleanupResult {
    readonly success: boolean;
    readonly errors: string[];
}
//# sourceMappingURL=session-cleanup.d.ts.map
