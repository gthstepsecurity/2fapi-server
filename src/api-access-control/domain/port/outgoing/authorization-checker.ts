// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Checks whether a client is authorized to access a given audience (service).
 * Called before token issuance to enforce authorization policies.
 */
export interface AuthorizationChecker {
  isAuthorized(clientIdentifier: string, audience: string): Promise<boolean>;
}
