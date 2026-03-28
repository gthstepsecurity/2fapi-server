// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Result } from "../../model/result.js";
/**
 * Driving port: seal (encrypt) the derived secret into a password-locked vault.
 */
export interface SealVault {
    execute(request: SealVaultRequest): Promise<Result<SealVaultResponse, SealVaultError>>;
}
export interface SealVaultRequest {
    readonly password: string;
    readonly passwordConfirmation: string;
    readonly secret: Uint8Array;
    readonly blinding: Uint8Array;
    readonly email: string;
    readonly tenantId: string;
    readonly clientId: string;
    readonly deviceId: string;
}
export interface SealVaultResponse {
    readonly deviceId: string;
}
export type SealVaultError = "PASSWORD_TOO_SHORT" | "PASSWORDS_DO_NOT_MATCH" | "CRYPTO_UNAVAILABLE" | "SERVER_UNREACHABLE" | "STORAGE_FULL";
//# sourceMappingURL=seal-vault.d.ts.map
