import { Commitment } from "../model/commitment.js";
// Note: deep import path — will be replaced by path alias (@shared/errors) when tsconfig paths are configured
import { EnrollmentError } from "../../../shared/errors.js";
export class EnrollmentPolicy {
    commitmentVerifier;
    proofVerifier;
    constructor(commitmentVerifier, proofVerifier) {
        this.commitmentVerifier = commitmentVerifier;
        this.proofVerifier = proofVerifier;
    }
    validate(commitmentBytes, proof, clientIdentifier) {
        if (commitmentBytes === undefined || commitmentBytes === null) {
            return new EnrollmentError("MISSING_COMMITMENT", "Commitment bytes are required");
        }
        if (!this.commitmentVerifier.isCanonical(commitmentBytes)) {
            return new EnrollmentError("INVALID_ENCODING", "Commitment encoding is not canonical");
        }
        if (!this.commitmentVerifier.isValidGroupElement(commitmentBytes)) {
            return new EnrollmentError("INVALID_GROUP_ELEMENT", "Commitment is not a valid group element");
        }
        if (this.commitmentVerifier.isIdentityElement(commitmentBytes)) {
            return new EnrollmentError("IDENTITY_ELEMENT", "Commitment must not be the identity element");
        }
        if (proof === undefined || proof === null) {
            return new EnrollmentError("MISSING_PROOF", "Proof of possession is required");
        }
        const commitment = Commitment.fromBytes(commitmentBytes);
        if (!this.proofVerifier.verify(commitment, proof, clientIdentifier)) {
            return new EnrollmentError("INVALID_PROOF", "Proof of possession is invalid");
        }
        return null;
    }
}
//# sourceMappingURL=enrollment-policy.js.map