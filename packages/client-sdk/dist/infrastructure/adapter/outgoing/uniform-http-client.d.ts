// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export declare class UniformHttpClient {
    private readonly baseUrl;
    private readonly fetch;
    constructor(baseUrl: string, fetch: typeof globalThis.fetch);
    /**
     * Send a vault operation through the single uniform endpoint.
     * All requests have identical external characteristics.
     */
    send(operation: VaultOperation, authToken?: string): Promise<VaultResponse>;
    /**
     * Send a dummy request (for request count normalization).
     * Identical to a real request from the outside.
     */
    sendDummy(): Promise<void>;
}
export type VaultOperation = {
    op: "seal";
    client_id: string;
    device_id: string;
    auth_token?: string;
} | {
    op: "evaluate";
    client_id: string;
    device_id: string;
    blinded_point: string;
    seal_token?: string;
} | {
    op: "unseal_result";
    client_id: string;
    device_id: string;
    eval_nonce: string;
    status: "success" | "failure";
} | {
    op: "dummy";
};
export type VaultResponse = Record<string, unknown>;
//# sourceMappingURL=uniform-http-client.d.ts.map
