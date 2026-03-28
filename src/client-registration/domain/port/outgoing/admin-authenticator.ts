// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Outgoing port for verifying admin identity credentials.
 * The domain requires that admin operations are authenticated,
 * but the actual verification mechanism is an infrastructure concern.
 */
export interface AdminAuthenticator {
  isValidAdmin(adminIdentity: string): Promise<boolean>;
}
