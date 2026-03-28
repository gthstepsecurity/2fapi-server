// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "./result.js";
/**
 * Value object representing a device password used to seal/unseal the vault.
 * Distinct from the 2FApi passphrase/PIN — this protects local storage only.
 */
export declare class DevicePassword {
    readonly value: string;
    private constructor();
    static create(raw: string): Result<DevicePassword, string>;
    matches(confirmation: string): boolean;
}
//# sourceMappingURL=device-password.d.ts.map
