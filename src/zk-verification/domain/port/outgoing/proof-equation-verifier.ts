// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Verifies the Sigma protocol equation: z_s·G + z_r·H == A + c·C
 * This port abstracts the actual elliptic curve operations (Ristretto255).
 * The implementation will use the Rust crypto core via napi-rs.
 *
 * NOTE: The current signature is synchronous. When WASM support is added
 * (browser target), a Promise-returning variant may be needed because
 * WASM module initialization is async. This will be addressed in a future
 * sprint, potentially via a separate AsyncProofEquationVerifier port.
 */
export interface ProofEquationVerifier {
  verify(params: {
    readonly generatorG: Uint8Array;
    readonly generatorH: Uint8Array;
    readonly commitment: Uint8Array;
    readonly announcement: Uint8Array;
    readonly challenge: Uint8Array;
    readonly responseS: Uint8Array;
    readonly responseR: Uint8Array;
  }): boolean;
}
