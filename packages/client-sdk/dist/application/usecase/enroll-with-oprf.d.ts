// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { CryptoEngine, DerivedSecret } from "../../domain/port/outgoing/crypto-engine.js";
import type { EnrollmentOprfGateway } from "../../domain/port/outgoing/enrollment-oprf-gateway.js";
/**
 * Enrollment use case with OPRF-hardened credential derivation (double-lock).
 *
 * Flow:
 * 1. Client: P = hash_to_group(passphrase), B = r·P (blind)
 * 2. Server: E = enrollment_key · B (evaluate in HSM)
 * 3. Client: U = r⁻¹·E (unblind)
 * 4. Client: (s, r) = HKDF(Argon2id(passphrase, salt) || U)
 * 5. Client: C = s·G + r·H → register commitment
 *
 * The enrollment_key NEVER leaves the HSM.
 * The passphrase NEVER reaches the server (only the blinded point B).
 * The commitment C CANNOT be brute-forced without both passphrase AND enrollment_key.
 */
export declare class EnrollWithOprfUseCase {
    private readonly crypto;
    private readonly enrollmentGateway;
    constructor(crypto: CryptoEngine, enrollmentGateway: EnrollmentOprfGateway);
    deriveSecret(params: OprfEnrollmentRequest): Promise<Result<OprfEnrollmentResult, OprfEnrollmentError>>;
}
export interface OprfEnrollmentRequest {
    readonly credential: string;
    readonly email: string;
    readonly tenantId: string;
}
export interface OprfEnrollmentResult {
    readonly secret: DerivedSecret;
    readonly commitment: Uint8Array;
}
export type OprfEnrollmentError = "SERVER_UNREACHABLE" | "DERIVATION_FAILED";
//# sourceMappingURL=enroll-with-oprf.d.ts.map
