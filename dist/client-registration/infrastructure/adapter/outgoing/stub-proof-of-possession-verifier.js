export class StubProofOfPossessionVerifier {
    validResult;
    constructor(validResult = true) {
        this.validResult = validResult;
    }
    verify(_commitment, _proof, _clientIdentifier) {
        return this.validResult;
    }
}
//# sourceMappingURL=stub-proof-of-possession-verifier.js.map