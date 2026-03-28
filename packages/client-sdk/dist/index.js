/**
 * @2fapi/client-sdk — 2FApi Client SDK
 *
 * Generate Pedersen commitments and Sigma proofs for Zero-Knowledge
 * API authentication. This SDK runs in the browser (via WASM) or
 * in Node.js (via napi-rs native module).
 *
 * @license Apache-2.0
 */
export { buildTranscript } from "./transcript.js";
export { PROTOCOL_VERSION, DOMAIN_SEPARATION_TAG, PROOF_BYTE_LENGTH, COMMITMENT_BYTE_LENGTH, } from "@2fapi/protocol-spec";
/**
 * Generate a Pedersen commitment C = s·G + r·H.
 *
 * @param secret - The client's secret scalar (32 bytes)
 * @param blindingFactor - The blinding factor scalar (32 bytes)
 * @returns The commitment as a compressed Ristretto255 point (32 bytes)
 *
 * NOTE: Requires @2fapi/crypto-wasm (browser) or @2fapi/crypto-native (Node.js).
 * These modules must be loaded before calling this function.
 */
export function generateCommitment(_secret, _blindingFactor) {
    if (!cryptoModule) {
        throw new Error("Crypto module not loaded. Call setCryptoModule() with @2fapi/crypto-wasm or @2fapi/crypto-native first.");
    }
    return cryptoModule.commit(_secret, _blindingFactor);
}
/**
 * Generate a Sigma proof of knowledge of (s, r) opening commitment C.
 */
export function generateProof(params) {
    if (!cryptoModule) {
        throw new Error("Crypto module not loaded. Call setCryptoModule() with @2fapi/crypto-wasm or @2fapi/crypto-native first.");
    }
    return cryptoModule.generateProof(params);
}
let cryptoModule = null;
/**
 * Set the cryptographic backend module.
 * Call this once at application startup before using generateCommitment/generateProof.
 *
 * @example
 * // Browser (WASM)
 * import * as wasm from "@2fapi/crypto-wasm";
 * setCryptoModule(wasm);
 *
 * // Node.js (native)
 * import * as native from "@2fapi/crypto-native";
 * setCryptoModule(native);
 */
export function setCryptoModule(module) {
    cryptoModule = module;
}
//# sourceMappingURL=index.js.map