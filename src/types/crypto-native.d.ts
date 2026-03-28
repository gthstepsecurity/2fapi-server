// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Type declarations for the @2fapi/crypto-native napi-rs module.
 *
 * This module is built from Rust via napi-rs and provides native
 * Ristretto255 cryptographic operations. The actual binary is only
 * available after `cargo build` in crypto-core/napi/.
 */
declare module "@2fapi/crypto-native" {
  export interface ProofEquationParams {
    generatorG: Buffer;
    generatorH: Buffer;
    commitment: Buffer;
    announcement: Buffer;
    challenge: Buffer;
    responseS: Buffer;
    responseR: Buffer;
  }

  export interface ProofGenerationParams {
    secret: Buffer;
    blinding: Buffer;
    commitment: Buffer;
    generatorG: Buffer;
    generatorH: Buffer;
    transcriptData: Buffer;
  }

  export function verifyProofEquation(params: ProofEquationParams): boolean;
  export function hashTranscript(data: Buffer): Buffer;
  export function isCanonicalPoint(bytes: Buffer): boolean;
  export function isCanonicalScalar(bytes: Buffer): boolean;
  export function isIdentityPoint(bytes: Buffer): boolean;
  export function generateProof(params: ProofGenerationParams): Buffer;
  export function commit(secret: Buffer, blinding: Buffer): Buffer;
  export function getGeneratorG(): Buffer;
  export function getGeneratorH(): Buffer;
}
