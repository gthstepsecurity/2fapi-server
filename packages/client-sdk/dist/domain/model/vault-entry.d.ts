// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
interface VaultEntryParams {
    readonly iv: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly tag: Uint8Array;
    readonly deviceId: string;
    readonly createdAtMs: number;
    readonly maxTtlHours: number;
    readonly version: number;
}
interface SerializedVaultEntry {
    readonly iv: string;
    readonly ciphertext: string;
    readonly tag: string;
    readonly deviceId: string;
    readonly createdAtMs: number;
    readonly maxTtlHours: number;
    readonly version: number;
}
/**
 * Value object representing an encrypted vault stored in localStorage.
 * Contains only the ciphertext and metadata — never the plaintext secret.
 */
export declare class VaultEntry {
    readonly iv: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly tag: Uint8Array;
    readonly deviceId: string;
    readonly createdAtMs: number;
    readonly maxTtlHours: number;
    readonly version: number;
    private constructor();
    static create(params: VaultEntryParams): VaultEntry;
    isExpired(nowMs: number): boolean;
    remainingHours(nowMs: number): number;
    isApproachingExpiry(nowMs: number): boolean;
    storageKey(email: string): string;
    serialize(): SerializedVaultEntry;
    static deserialize(data: SerializedVaultEntry): VaultEntry;
}
export {};
//# sourceMappingURL=vault-entry.d.ts.map
