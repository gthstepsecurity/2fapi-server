// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Immutable value object representing a server-side OPRF key.
 * The key is a random 256-bit scalar used for blind evaluation.
 * Stored only on the server — never sent to the client.
 */
export declare class OprfKey {
    readonly clientId: string;
    readonly deviceId: string;
    readonly value: Uint8Array;
    readonly isDestroyed: boolean;
    private constructor();
    static generate(clientId: string, deviceId: string): OprfKey;
    static restore(clientId: string, deviceId: string, value: Uint8Array, isDestroyed: boolean): OprfKey;
    valueForEvaluation(): Uint8Array;
    destroy(): OprfKey;
}
//# sourceMappingURL=oprf-key.d.ts.map
