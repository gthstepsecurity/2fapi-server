import type { ProofOfPossessionVerifier, ProofOfPossessionData } from "../../../domain/port/outgoing/proof-of-possession-verifier.js";
import type { Commitment } from "../../../domain/model/commitment.js";
export declare class StubProofOfPossessionVerifier implements ProofOfPossessionVerifier {
    private readonly validResult;
    constructor(validResult?: boolean);
    verify(_commitment: Commitment, _proof: ProofOfPossessionData, _clientIdentifier: string): boolean;
}
//# sourceMappingURL=stub-proof-of-possession-verifier.d.ts.map