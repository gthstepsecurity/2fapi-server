// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Outgoing port for cryptographically secure random number generation.
 * The domain needs random indices for word selection;
 * the actual CSPRNG implementation is an infrastructure concern.
 */
export interface SecureRandomProvider {
  /** Returns a cryptographically secure random integer in [0, max) */
  randomIndex(max: number): number;
}
