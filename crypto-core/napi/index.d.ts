// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/* Auto-generated TypeScript declarations for @2fapi/crypto-native */

/**
 * Parameters for verifying the Sigma protocol equation:
 * z_s·G + z_r·H == A + c·C
 */
export interface ProofEquationParams {
  /** Compressed Ristretto255 generator G (32 bytes). */
  generatorG: Buffer;
  /** Compressed Ristretto255 generator H (32 bytes). */
  generatorH: Buffer;
  /** Compressed commitment point C (32 bytes). */
  commitment: Buffer;
  /** Compressed announcement point A (32 bytes). */
  announcement: Buffer;
  /** Challenge scalar c (32 bytes, canonical). */
  challenge: Buffer;
  /** Response scalar z_s (32 bytes, canonical). */
  responseS: Buffer;
  /** Response scalar z_r (32 bytes, canonical). */
  responseR: Buffer;
}

/**
 * Parameters for generating a Sigma proof.
 */
export interface ProofGenerationParams {
  /** Secret scalar s (32 bytes). */
  secret: Buffer;
  /** Blinding scalar r (32 bytes). */
  blinding: Buffer;
  /** Compressed commitment point C (32 bytes). */
  commitment: Buffer;
  /** Compressed generator G (32 bytes). */
  generatorG: Buffer;
  /** Compressed generator H (32 bytes). */
  generatorH: Buffer;
  /** Transcript context bytes (variable length). */
  transcriptData: Buffer;
}

/**
 * Verifies the Sigma protocol equation: z_s·G + z_r·H == A + c·C.
 * Returns true if the equation holds.
 * Throws on invalid input encodings (non-canonical points/scalars).
 */
export function verifyProofEquation(params: ProofEquationParams): boolean;

/**
 * Computes the Fiat-Shamir transcript hash (SHA-512 reduced to scalar).
 * Returns 32-byte canonical scalar.
 */
export function hashTranscript(data: Buffer): Buffer;

/**
 * Checks whether 32 bytes are a canonical Ristretto255 point encoding.
 * Returns false for non-32-byte inputs.
 */
export function isCanonicalPoint(bytes: Buffer): boolean;

/**
 * Checks whether 32 bytes are a canonical scalar (reduced modulo l).
 * Returns false for non-32-byte inputs.
 */
export function isCanonicalScalar(bytes: Buffer): boolean;

/**
 * Checks whether 32 bytes encode the Ristretto255 identity element.
 * Returns false for non-32-byte inputs.
 */
export function isIdentityPoint(bytes: Buffer): boolean;

/**
 * Generates a Sigma proof of knowledge of (s, r) such that C = s·G + r·H.
 * Returns 96 bytes: announcement (32) || response_s (32) || response_r (32).
 */
export function generateProof(params: ProofGenerationParams): Buffer;

/**
 * Computes a Pedersen commitment C = s·G + r·H.
 * Returns compressed commitment point (32 bytes).
 */
export function commit(secret: Buffer, blinding: Buffer): Buffer;

/**
 * Returns the compressed Ristretto255 basepoint G (32 bytes).
 * G is the standard Ristretto255 basepoint from curve25519-dalek.
 */
export declare function getGeneratorG(): Buffer;

/**
 * Returns the compressed secondary generator H (32 bytes).
 * H is derived via hash-to-point with domain separator "2FApi-Pedersen-GeneratorH-v1".
 */
export declare function getGeneratorH(): Buffer;

/**
 * Constant-time equality comparison using subtle::ConstantTimeEq.
 *
 * Returns false for inputs of different lengths without leaking
 * the length difference via timing. No panic on any input.
 */
export function constantTimeEq(a: Buffer, b: Buffer): boolean;
