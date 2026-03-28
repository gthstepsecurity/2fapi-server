import type { ProofOfPossessionData } from "../outgoing/proof-of-possession-verifier.js";
export interface EnrollClientRequest {
    clientIdentifier: string;
    commitmentBytes: Uint8Array;
    proofOfPossession: ProofOfPossessionData;
}
export type EnrollClientResponse = {
    success: true;
    referenceId: string;
    clientIdentifier: string;
} | {
    success: false;
    error: "enrollment_failed";
};
export interface EnrollClient {
    execute(request: EnrollClientRequest): Promise<EnrollClientResponse>;
}
//# sourceMappingURL=enroll-client.d.ts.map