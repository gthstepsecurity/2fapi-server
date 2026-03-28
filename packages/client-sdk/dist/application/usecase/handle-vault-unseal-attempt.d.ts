// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { VaultPepperStore } from "../../domain/port/outgoing/vault-pepper-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";
interface DeviceIdentifier {
    readonly clientId: string;
    readonly deviceId: string;
}
export type HandleUnsealResponse = {
    readonly status: "allowed";
    readonly pepper: Uint8Array;
    readonly attemptsRemaining: number;
} | {
    readonly status: "wiped";
};
/**
 * Server-side use case: validate an unseal attempt and deliver the pepper.
 * - Checks the attempt counter
 * - If under threshold: delivers the pepper
 * - If wiped: destroys the pepper permanently and returns "wiped"
 */
export declare class HandleVaultUnsealAttemptUseCase {
    private readonly pepperStore;
    private readonly attemptStore;
    constructor(pepperStore: VaultPepperStore, attemptStore: VaultAttemptStore);
    execute(params: DeviceIdentifier): Promise<Result<HandleUnsealResponse, string>>;
    reportFailure(params: DeviceIdentifier): Promise<void>;
    reportSuccess(params: DeviceIdentifier): Promise<void>;
}
export {};
//# sourceMappingURL=handle-vault-unseal-attempt.d.ts.map
