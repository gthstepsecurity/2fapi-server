// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object for protocol version negotiation.
 * Ensures WASM module and server agree on transcript format.
 */
export declare class ProtocolVersion {
    readonly major: number;
    readonly minor: number;
    private constructor();
    static readonly CURRENT: ProtocolVersion;
    static parse(version: string): ProtocolVersion | null;
    isCompatibleWith(other: ProtocolVersion): boolean;
    toString(): string;
}
//# sourceMappingURL=protocol-version.d.ts.map
