// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Checks whether a client is currently active or revoked.
 * Called dynamically at every token validation to ensure
 * revoked clients are denied immediately.
 */
export interface ClientStatusChecker {
  isActive(clientIdentifier: string): Promise<boolean>;
}
