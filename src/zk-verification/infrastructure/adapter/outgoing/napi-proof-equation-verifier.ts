// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ProofEquationVerifier } from "../../../domain/port/outgoing/proof-equation-verifier.js";

/**
 * Contract for the native crypto module used by napi adapters.
 * Mirrors the @2fapi/crypto-native exports needed for proof verification.
 */
export interface NativeCryptoModule {
  verifyProofEquation(params: {
    generatorG: Buffer;
    generatorH: Buffer;
    commitment: Buffer;
    announcement: Buffer;
    challenge: Buffer;
    responseS: Buffer;
    responseR: Buffer;
  }): boolean;
}

/**
 * Real implementation of ProofEquationVerifier using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Verifies the Sigma protocol equation: z_s·G + z_r·H == A + c·C
 * over Ristretto255 using constant-time operations in Rust.
 */
export class NapiProofEquationVerifier implements ProofEquationVerifier {
  constructor(private readonly nativeModule: NativeCryptoModule) {}

  verify(params: {
    readonly generatorG: Uint8Array;
    readonly generatorH: Uint8Array;
    readonly commitment: Uint8Array;
    readonly announcement: Uint8Array;
    readonly challenge: Uint8Array;
    readonly responseS: Uint8Array;
    readonly responseR: Uint8Array;
  }): boolean {
    try {
      return this.nativeModule.verifyProofEquation({
        generatorG: Buffer.from(params.generatorG),
        generatorH: Buffer.from(params.generatorH),
        commitment: Buffer.from(params.commitment),
        announcement: Buffer.from(params.announcement),
        challenge: Buffer.from(params.challenge),
        responseS: Buffer.from(params.responseS),
        responseR: Buffer.from(params.responseR),
      });
    } catch {
      // Native module errors (invalid encodings, etc.) are treated as
      // verification failure rather than propagated as exceptions.
      return false;
    }
  }
}
