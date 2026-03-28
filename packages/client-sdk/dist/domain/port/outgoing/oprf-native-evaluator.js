/**
 * Stub evaluator for domain-level tests.
 * NOT cryptographically valid — uses XOR. MUST NOT be used in production.
 */
export class StubOprfEvaluator {
    evaluate(blindedPoint, oprfKey) {
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
export class NapiOprfEvaluator {
    napiModule;
    constructor(napiModule) {
        this.napiModule = napiModule;
    }
    evaluate(blindedPoint, oprfKey) {
        return this.napiModule.oprf_evaluate(blindedPoint, oprfKey);
    }
}
/**
 * WASM evaluator — calls Rust crypto-core oprf::evaluate() via wasm-bindgen.
 * This is the PRODUCTION implementation for browser environments.
 */
export class WasmOprfEvaluator {
    wasmModule;
    constructor(wasmModule) {
        this.wasmModule = wasmModule;
    }
    evaluate(blindedPoint, oprfKey) {
        return new Uint8Array(this.wasmModule.oprf_evaluate(blindedPoint, oprfKey));
    }
}
//# sourceMappingURL=oprf-native-evaluator.js.map