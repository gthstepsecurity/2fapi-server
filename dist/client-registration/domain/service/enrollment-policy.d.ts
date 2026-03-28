import type { CommitmentVerifier } from "../port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "../port/outgoing/proof-of-possession-verifier.js";
import type { ProofOfPossessionData } from "../port/outgoing/proof-of-possession-verifier.js";
import { EnrollmentError } from "../../../shared/errors.js";
export declare class EnrollmentPolicy {
    private readonly commitmentVerifier;
    private readonly proofVerifier;
    constructor(commitmentVerifier: CommitmentVerifier, proofVerifier: ProofOfPossessionVerifier);
    validate(commitmentBytes: Uint8Array | undefined, proof: ProofOfPossessionData | undefined, clientIdentifier: string): EnrollmentError | null;
}
//# sourceMappingURL=enrollment-policy.d.ts.map