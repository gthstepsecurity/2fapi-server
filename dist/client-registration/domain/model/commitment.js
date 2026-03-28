const COMMITMENT_BYTE_LENGTH = 32;
export class Commitment {
    bytes;
    constructor(bytes) {
        this.bytes = new Uint8Array(bytes);
    }
    static fromBytes(bytes) {
        if (bytes.length !== COMMITMENT_BYTE_LENGTH) {
            // Note: error message includes byte length for developer debugging.
            // This is safe because domain errors are never exposed to external clients
            // (the use case returns a generic "enrollment_failed" response).
            throw new Error(`Commitment must be exactly 32 bytes, got ${bytes.length}`);
        }
        // Defense in depth: the identity element (32 zero bytes in Ristretto255)
        // is also rejected by CommitmentVerifier.isIdentityElement() in the enrollment pipeline.
        // This check prevents construction of an invalid Commitment value object at the type level.
        if (bytes.every((b) => b === 0)) {
            throw new Error("Commitment cannot be the identity element (32 zero bytes in Ristretto255)");
        }
        return new Commitment(bytes);
    }
    toBytes() {
        return new Uint8Array(this.bytes);
    }
    /** Byte-exact comparison. NOTE: This is NOT constant-time.
     *  Do not use in cryptographic verification paths. */
    equals(other) {
        if (this.bytes.length !== other.bytes.length)
            return false;
        for (let i = 0; i < this.bytes.length; i++) {
            if (this.bytes[i] !== other.bytes[i])
                return false;
        }
        return true;
    }
}
//# sourceMappingURL=commitment.js.map