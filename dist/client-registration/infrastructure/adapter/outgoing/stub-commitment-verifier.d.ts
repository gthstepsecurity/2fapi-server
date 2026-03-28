import type { CommitmentVerifier } from "../../../domain/port/outgoing/commitment-verifier.js";
export interface StubCommitmentVerifierConfig {
    isCanonical?: boolean;
    isValidGroupElement?: boolean;
    isIdentityElement?: boolean;
}
export declare class StubCommitmentVerifier implements CommitmentVerifier {
    private readonly config;
    constructor(config?: StubCommitmentVerifierConfig);
    isCanonical(_bytes: Uint8Array): boolean;
    isValidGroupElement(_bytes: Uint8Array): boolean;
    isIdentityElement(_bytes: Uint8Array): boolean;
}
//# sourceMappingURL=stub-commitment-verifier.d.ts.map