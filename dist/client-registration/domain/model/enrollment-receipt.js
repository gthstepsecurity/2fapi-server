export class EnrollmentReceipt {
    referenceId;
    clientIdentifier;
    constructor(referenceId, clientIdentifier) {
        this.referenceId = referenceId;
        this.clientIdentifier = clientIdentifier;
    }
    equals(other) {
        return (this.referenceId === other.referenceId &&
            this.clientIdentifier === other.clientIdentifier);
    }
}
//# sourceMappingURL=enrollment-receipt.js.map