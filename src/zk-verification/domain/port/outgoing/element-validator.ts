// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Validates cryptographic elements (points and scalars) for canonical encoding.
 * The implementation will use the Rust crypto core for Ristretto255 validation.
 */
export interface ElementValidator {
  isCanonicalScalar(bytes: Uint8Array): boolean;
  isCanonicalPoint(bytes: Uint8Array): boolean;
}
