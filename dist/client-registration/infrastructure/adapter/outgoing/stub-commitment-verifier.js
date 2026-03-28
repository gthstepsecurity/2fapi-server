export class StubCommitmentVerifier {
    config;
    constructor(config = {}) {
        this.config = {
            isCanonical: config.isCanonical ?? true,
            isValidGroupElement: config.isValidGroupElement ?? true,
            isIdentityElement: config.isIdentityElement ?? false,
        };
    }
    isCanonical(_bytes) {
        return this.config.isCanonical;
    }
    isValidGroupElement(_bytes) {
        return this.config.isValidGroupElement;
    }
    isIdentityElement(_bytes) {
        return this.config.isIdentityElement;
    }
}
//# sourceMappingURL=stub-commitment-verifier.js.map