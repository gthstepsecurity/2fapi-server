// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for client-side OPRF server interaction.
 * The client sends a blinded point, the server evaluates blindly.
 */
export interface OprfGateway {
    /**
     * Request OPRF evaluation from the server.
     * Client sends blinded point B, server returns evaluated point E.
     */
    requestEvaluation(params: OprfEvaluationRequest): Promise<OprfEvaluationResponse>;
    /**
     * Notify the server that an unseal attempt failed (wrong password / GCM mismatch).
     */
    reportFailure(clientId: string, deviceId: string): Promise<void>;
}
export interface OprfEvaluationRequest {
    readonly clientId: string;
    readonly deviceId: string;
    readonly blindedPoint: Uint8Array;
}
export type OprfEvaluationResponse = {
    readonly status: "allowed";
    readonly evaluated: Uint8Array;
    readonly attemptsRemaining: number;
} | {
    readonly status: "wiped";
};
//# sourceMappingURL=oprf-gateway.d.ts.map
