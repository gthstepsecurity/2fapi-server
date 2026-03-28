// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for enrollment OPRF evaluation.
 * The enrollment OPRF key is per-tenant (NOT per-device like the vault OPRF key).
 * It protects the credential derivation so that the public commitment C
 * cannot be brute-forced offline without server cooperation.
 *
 * The enrollment OPRF key NEVER leaves the HSM. The passphrase NEVER reaches the server.
 */
export interface EnrollmentOprfGateway {
  /**
   * Request enrollment OPRF evaluation.
   * Client sends blinded hash_to_group(passphrase), server evaluates blindly.
   */
  evaluate(params: EnrollmentOprfRequest): Promise<EnrollmentOprfResponse>;
}

export interface EnrollmentOprfRequest {
  readonly tenantId: string;
  readonly blindedPoint: Uint8Array;
}

export interface EnrollmentOprfResponse {
  readonly evaluated: Uint8Array;
}
