// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for distributed Sigma proof generation (server's contribution).
 *
 * The server holds share (s2, r2). When the client requests a partial
 * response, the server computes z_s2 = c·s2, z_r2 = c·r2 and returns
 * the partial scalars. The client combines them with its own partial
 * to produce a valid proof — WITHOUT ever reconstructing the full secret.
 */
export interface DistributedProofGateway {
    /**
     * Request the server's partial Sigma response.
     *
     * The server uses its share (s2, r2) from the HSM and the provided
     * challenge scalar to compute z_s2 = c·s2, z_r2 = c·r2.
     */
    requestPartialResponse(params: ServerPartialRequest): Promise<ServerPartialResponse>;
}
export interface ServerPartialRequest {
    readonly clientId: string;
    readonly deviceId: string;
    readonly challenge: Uint8Array;
    readonly announcement: Uint8Array;
    readonly context: Uint8Array;
}
export interface ServerPartialResponse {
    readonly z_s_partial: Uint8Array;
    readonly z_r_partial: Uint8Array;
}
//# sourceMappingURL=distributed-proof-gateway.d.ts.map
