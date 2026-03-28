// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../../domain/model/result.js";
import type { OprfKeyStore } from "../../domain/port/outgoing/oprf-key-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";
import type { OprfNativeEvaluator } from "../../domain/port/outgoing/oprf-native-evaluator.js";
interface DeviceIdentifier {
    readonly clientId: string;
    readonly deviceId: string;
}
interface EvaluateRequest extends DeviceIdentifier {
    readonly blindedPoint: Uint8Array;
}
export type EvaluateResponse = {
    readonly status: "allowed";
    readonly evaluated: Uint8Array;
    readonly attemptsRemaining: number;
} | {
    readonly status: "wiped";
};
export type EvaluateError = "INVALID_BLINDED_ELEMENT" | "NO_VAULT_REGISTERED";
interface SealResponse {
    readonly status: "ready";
    readonly deviceId: string;
}
/**
 * Server-side use case: OPRF evaluation.
 *
 * R2-01 FIX: The scalar multiplication E = k · B is performed by an
 * injected OprfNativeEvaluator (port pattern):
 *   - Production: NapiOprfEvaluator (Rust crypto-core via napi-rs)
 *   - Browser: WasmOprfEvaluator (Rust crypto-core via wasm-bindgen)
 *   - Tests: StubOprfEvaluator (XOR, domain-level only, BLOCKED in production)
 *
 * The XOR simulation is no longer embedded in this use case.
 */
export declare class HandleOprfEvaluateUseCase {
    private readonly keyStore;
    private readonly attemptStore;
    private readonly evaluator;
    constructor(keyStore: OprfKeyStore, attemptStore: VaultAttemptStore, evaluator?: OprfNativeEvaluator);
    evaluate(request: EvaluateRequest): Promise<Result<EvaluateResponse, EvaluateError>>;
    seal(params: DeviceIdentifier): Promise<Result<SealResponse, string>>;
    reportFailure(params: DeviceIdentifier): Promise<void>;
    reportSuccess(params: DeviceIdentifier): Promise<void>;
}
export {};
//# sourceMappingURL=handle-oprf-evaluate.d.ts.map
