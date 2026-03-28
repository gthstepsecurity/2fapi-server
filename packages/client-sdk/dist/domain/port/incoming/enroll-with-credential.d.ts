// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Result } from "../../model/result.js";
/**
 * Driving port: full enrollment flow from credential to device protection.
 */
export interface EnrollWithCredential {
    execute(request: EnrollmentRequest): Promise<Result<EnrollmentResponse, EnrollmentError>>;
}
export interface EnrollmentRequest {
    readonly email: string;
    readonly tenantId: string;
    readonly credential: string;
    readonly credentialType: "passphrase" | "pin";
    readonly deviceProtection: "biometric" | "password" | "none";
    readonly devicePassword?: string;
    readonly devicePasswordConfirmation?: string;
}
export interface EnrollmentResponse {
    readonly clientId: string;
    readonly commitment: Uint8Array;
    readonly recoveryWords: readonly string[];
    readonly deviceId: string;
    readonly tier: 0 | 1 | 2;
}
export type EnrollmentError = "INVALID_CREDENTIAL" | "CREDENTIAL_CONFIRMATION_FAILED" | "COMMITMENT_REGISTRATION_FAILED" | "VAULT_SEAL_FAILED" | "BIOMETRIC_SETUP_FAILED" | "WASM_NOT_AVAILABLE";
//# sourceMappingURL=enroll-with-credential.d.ts.map
