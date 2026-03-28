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
export class StubOprfEvaluator implements OprfNativeEvaluator {
  evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array {
    if (typeof process !== "undefined") {
      const env = process.env["TWOFAPI_ENV"] ?? process.env["NODE_ENV"] ?? "";
      if (env === "production") {
        throw new Error("CRITICAL: StubOprfEvaluator MUST NOT run in production.");
      }
    }
    const result = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      result[i] = (blindedPoint[i] ?? 0) ^ (oprfKey[i] ?? 0);
    }
    return result;
  }
}

/**
 * NAPI evaluator — calls Rust crypto-core oprf::evaluate() via napi-rs.
 * This is the PRODUCTION implementation for Node.js servers.
 */
export class NapiOprfEvaluator implements OprfNativeEvaluator {
  constructor(private readonly napiModule: NapiCryptoModule) {}

  evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array {
    return this.napiModule.oprf_evaluate(blindedPoint, oprfKey);
  }
}

/**
 * WASM evaluator — calls Rust crypto-core oprf::evaluate() via wasm-bindgen.
 * This is the PRODUCTION implementation for browser environments.
 */
export class WasmOprfEvaluator implements OprfNativeEvaluator {
  constructor(private readonly wasmModule: WasmCryptoModule) {}

  evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array {
    return new Uint8Array(this.wasmModule.oprf_evaluate(blindedPoint, oprfKey));
  }
}

/** Minimal interface for the NAPI crypto module */
export interface NapiCryptoModule {
  oprf_evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}

/** Minimal interface for the WASM crypto module */
export interface WasmCryptoModule {
  oprf_evaluate(blindedPoint: Uint8Array, oprfKey: Uint8Array): Uint8Array;
}
