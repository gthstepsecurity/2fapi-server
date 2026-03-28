// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultServerGateway, SealRequest, SealResponse, UnsealRequest, UnsealResponse, UnsealFailureReport, AuthSuccessReport } from "../../../domain/port/outgoing/vault-server-gateway.js";
/**
 * Infrastructure adapter: communicates with the 2FApi server for vault operations.
 * Handles pepper delivery, attempt counter, and lifecycle notifications.
 */
export declare class HttpVaultServerGateway implements VaultServerGateway {
    private readonly baseUrl;
    private readonly fetch;
    constructor(baseUrl: string, fetch: typeof globalThis.fetch);
    requestSeal(params: SealRequest): Promise<SealResponse>;
    requestUnseal(params: UnsealRequest): Promise<UnsealResponse>;
    reportUnsealFailure(params: UnsealFailureReport): Promise<void>;
    reportAuthSuccess(params: AuthSuccessReport): Promise<void>;
    deleteVaultRegistration(clientId: string, deviceId: string): Promise<void>;
    private post;
}
//# sourceMappingURL=http-vault-server-gateway.d.ts.map
