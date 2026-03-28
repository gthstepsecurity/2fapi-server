// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
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
export type {
  TranscriptFields,
  ProofData,
  ChallengeData,
  CommitmentData,
} from "@2fapi/protocol-spec";
export {
  PROTOCOL_VERSION,
  DOMAIN_SEPARATION_TAG,
  PROOF_BYTE_LENGTH,
  COMMITMENT_BYTE_LENGTH,
} from "@2fapi/protocol-spec";

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
export function generateCommitment(
  _secret: Uint8Array,
  _blindingFactor: Uint8Array,
): Uint8Array {
  if (!cryptoModule) {
    throw new Error(
      "Crypto module not loaded. Call setCryptoModule() with @2fapi/crypto-wasm or @2fapi/crypto-native first.",
    );
  }
  return cryptoModule.commit(_secret, _blindingFactor);
}

/**
 * Generate a Sigma proof of knowledge of (s, r) opening commitment C.
 */
export function generateProof(params: {
  readonly secret: Uint8Array;
  readonly blindingFactor: Uint8Array;
  readonly commitment: Uint8Array;
  readonly nonce: Uint8Array;
  readonly channelBinding: Uint8Array;
  readonly clientIdentifier: string;
  readonly domainSeparationTag?: string;
}): Uint8Array {
  if (!cryptoModule) {
    throw new Error(
      "Crypto module not loaded. Call setCryptoModule() with @2fapi/crypto-wasm or @2fapi/crypto-native first.",
    );
  }
  return cryptoModule.generateProof(params);
}

// --- Crypto Module Injection ---

interface CryptoModule {
  commit(secret: Uint8Array, blindingFactor: Uint8Array): Uint8Array;
  generateProof(params: Record<string, unknown>): Uint8Array;
}

let cryptoModule: CryptoModule | null = null;

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
export function setCryptoModule(module: CryptoModule): void {
  cryptoModule = module;
}
