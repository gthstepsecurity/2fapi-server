import { ok, err } from "../../domain/model/result.js";
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
    crypto;
    enrollmentGateway;
    constructor(crypto, enrollmentGateway) {
        this.crypto = crypto;
        this.enrollmentGateway = enrollmentGateway;
    }
    async deriveSecret(params) {
        // 1. OPRF blind the passphrase
        const { blindedPoint, blindingFactor } = this.crypto.oprfBlind(params.credential);
        // 2. Send blinded point to server for enrollment OPRF evaluation
        let evaluated;
        try {
            const response = await this.enrollmentGateway.evaluate({
                tenantId: params.tenantId,
                blindedPoint,
            });
            evaluated = response.evaluated;
        }
        catch {
            return err("SERVER_UNREACHABLE");
        }
        // 3. Unblind → enrollment OPRF output U
        const oprfOutput = this.crypto.oprfUnblind(evaluated, blindingFactor);
        // 4. Zeroize blinding factor
        this.crypto.zeroize(blindingFactor);
        // 5. Double-lock derivation: Argon2id(passphrase) + OPRF output
        let secret;
        try {
            secret = await this.crypto.deriveCredentialWithOprf(params.credential, params.email, params.tenantId, oprfOutput);
        }
        finally {
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
//# sourceMappingURL=enroll-with-oprf.js.map