// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for native OPRF scalar multiplication (R2-01 fix).
 *
 * This replaces the simulateOprfEval XOR stub with a proper
 * cryptographic operation: E = k · B over Ristretto255.
 *
 * Implementations:
 * - NapiOprfEvaluator: calls crypto-core via napi-rs (Node.js server)
 * - WasmOprfEvaluator: calls crypto-core via wasm-bindgen (browser)
 * - StubOprfEvaluator: XOR simulation for domain-level tests ONLY
 */
export interface OprfNativeEvaluator {
    /**
     * Compute E = oprfKey · blindedPoint (Ristretto255 scalar multiplication).
     *
     * @param blindedPoint - 32-byte compressed Ristretto point from the client
     * @param oprfKey - 32-byte scalar (the server's OPRF key)
     * @returns 32-byte compressed Ristretto point (the evaluated result)
     * @throws if blindedPoint is not a valid canonical Ristretto point
     * @throws if the result is the identity element
     */
    evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
/**
 * Stub evaluator for domain-level tests.
 * NOT cryptographically valid — uses XOR. MUST NOT be used in production.
 */
export declare class StubOprfEvaluator implements OprfNativeEvaluator {
    evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
/**
 * NAPI evaluator — calls Rust crypto-core oprf::evaluate() via napi-rs.
 * This is the PRODUCTION implementation for Node.js servers.
 */
export declare class NapiOprfEvaluator implements OprfNativeEvaluator {
    private readonly napiModule;
    constructor(napiModule: NapiCryptoModule);
    evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
/**
 * WASM evaluator — calls Rust crypto-core oprf::evaluate() via wasm-bindgen.
 * This is the PRODUCTION implementation for browser environments.
 */
export declare class WasmOprfEvaluator implements OprfNativeEvaluator {
    private readonly wasmModule;
    constructor(wasmModule: WasmCryptoModule);
    evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
/** Minimal interface for the NAPI crypto module */
export interface NapiCryptoModule {
    oprf_evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
/** Minimal interface for the WASM crypto module */
export interface WasmCryptoModule {
    oprf_evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
//# sourceMappingURL=oprf-native-evaluator.d.ts.map
