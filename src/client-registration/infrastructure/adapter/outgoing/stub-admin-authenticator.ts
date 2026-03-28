// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AdminAuthenticator } from "../../../domain/port/outgoing/admin-authenticator.js";

/**
 * Stub admin authenticator that accepts all non-empty admin identities.
 * Suitable for testing and development environments.
 * Production environments MUST use a real implementation.
 */
export class StubAdminAuthenticator implements AdminAuthenticator {
  async isValidAdmin(adminIdentity: string): Promise<boolean> {
    return adminIdentity.length > 0;
  }
}
