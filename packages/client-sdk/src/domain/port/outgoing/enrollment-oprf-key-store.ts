// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Server-side port: stores enrollment OPRF keys per user (R15-02 fix).
 *
 * Per-user keys limit the blast radius of a breach — compromising one user's
 * enrollment key affects only that user, not the entire tenant.
 *
 * Key lifecycle:
 * - Created during first enrollment
 * - Reused for all devices of the same user
 * - Rotated on passphrase change
 * - Stored in HSM (non-extractable)
 */
export interface EnrollmentOprfKeyStore {
  /** Generate and store a new enrollment OPRF key for a user. */
  generate(tenantId: string, clientId: string): Promise<void>;

  /** Check if an enrollment key exists for this user. */
  exists(tenantId: string, clientId: string): Promise<boolean>;

  /**
   * Evaluate OPRF blindly (scalar multiplication inside HSM).
   * The key NEVER leaves the store — only the evaluated point is returned.
   */
  evaluate(tenantId: string, clientId: string, blindedPoint: Uint8Array): Promise<Uint8Array>;

  /** Delete the enrollment key (on account deletion). */
  delete(tenantId: string, clientId: string): Promise<void>;
}
