// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Verifies signature on token bytes using EdDSA.
 * Returns the payload bytes if signature is valid, null otherwise.
 */
export interface TokenVerifier {
  verify(signedToken: Uint8Array): Promise<Uint8Array | null>;
}
