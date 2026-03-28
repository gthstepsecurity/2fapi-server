// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
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
export class EnrollWithOprfUseCase {
  constructor(
    private readonly crypto: CryptoEngine,
    private readonly enrollmentGateway: EnrollmentOprfGateway,
  ) {}

  async deriveSecret(params: OprfEnrollmentRequest): Promise<Result<OprfEnrollmentResult, OprfEnrollmentError>> {
    // 1. OPRF blind the passphrase
    const { blindedPoint, blindingFactor } = this.crypto.oprfBlind(params.credential);

    // 2. Send blinded point to server for enrollment OPRF evaluation
    let evaluated: Uint8Array;
    try {
      const response = await this.enrollmentGateway.evaluate({
        tenantId: params.tenantId,
        blindedPoint,
      });
      evaluated = response.evaluated;
    } catch {
      return err("SERVER_UNREACHABLE");
    }

    // 3. Unblind → enrollment OPRF output U
    const oprfOutput = this.crypto.oprfUnblind(evaluated, blindingFactor);

    // 4. Zeroize blinding factor
    this.crypto.zeroize(blindingFactor);

    // 5. Double-lock derivation: Argon2id(passphrase) + OPRF output
    let secret: DerivedSecret;
    try {
      secret = await this.crypto.deriveCredentialWithOprf(
        params.credential,
        params.email,
        params.tenantId,
        oprfOutput,
      );
    } finally {
      this.crypto.zeroize(oprfOutput);
    }

    // 6. Compute commitment
    const commitment = this.crypto.computeCommitment(secret.secret, secret.blinding);

    return ok({
      secret,
      commitment,
    });
  }
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

export type OprfEnrollmentError =
  | "SERVER_UNREACHABLE"
  | "DERIVATION_FAILED";
