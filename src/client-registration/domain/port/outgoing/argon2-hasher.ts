// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Parameters for Argon2id key derivation.
 */
export interface Argon2Params {
  /** Memory cost in KB (e.g., 65536 = 64 MB) */
  readonly memory: number;
  /** Number of iterations */
  readonly iterations: number;
  /** Degree of parallelism */
  readonly parallelism: number;
  /** Output hash length in bytes */
  readonly hashLength: number;
}

/**
 * Outgoing port for Argon2id hashing operations.
 * The domain requires hashing and verification of recovery keys;
 * the actual Argon2id implementation is an infrastructure concern.
 *
 * In tests, a SHA-256 stub can be used instead of real Argon2id.
 */
export interface Argon2Hasher {
  /** Hashes the input with the given salt and parameters */
  hash(input: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array>;

  /** Verifies that the input matches the expected hash */
  verify(input: Uint8Array, salt: Uint8Array, expected: Uint8Array, params: Argon2Params): Promise<boolean>;
}
