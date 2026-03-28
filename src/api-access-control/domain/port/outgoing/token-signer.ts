// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Signs token payload bytes using EdDSA.
 * The implementation is in infrastructure (crypto adapter).
 */
export interface TokenSigner {
  sign(payload: Uint8Array): Promise<Uint8Array>;
}
