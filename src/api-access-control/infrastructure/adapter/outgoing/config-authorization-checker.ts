// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuthorizationChecker } from "../../../domain/port/outgoing/authorization-checker.js";

/**
 * Configuration-based authorization checker for the API Access Control context.
 *
 * Checks client-audience authorization against a configurable allowlist.
 * When no explicit configuration is provided, defaults to DENYING all
 * audiences (fail-closed) to prevent accidental unrestricted access.
 *
 * For fine-grained authorization, supply a mapping of client identifiers
 * to their allowed audiences.
 */
export class ConfigAuthorizationChecker implements AuthorizationChecker {
  private readonly allowedAudiences: ReadonlyMap<string, ReadonlySet<string>> | null;

  /**
   * @param audienceConfig - Optional map of clientIdentifier -> allowed audiences.
   *   If null/undefined, all requests are DENIED (fail-closed mode).
   */
  constructor(audienceConfig?: Record<string, string[]>) {
    if (audienceConfig) {
      const map = new Map<string, ReadonlySet<string>>();
      for (const [client, audiences] of Object.entries(audienceConfig)) {
        map.set(client, new Set(audiences));
      }
      this.allowedAudiences = map;
    } else {
      this.allowedAudiences = null;
      console.warn(
        "[ConfigAuthorizationChecker] WARNING: no audience configuration provided — all requests will be denied. " +
        "Supply an audienceConfig to allow access.",
      );
    }
  }

  async isAuthorized(clientIdentifier: string, audience: string): Promise<boolean> {
    // Fail-closed: no config means deny all requests
    if (this.allowedAudiences === null) {
      return false;
    }

    const allowed = this.allowedAudiences.get(clientIdentifier);
    if (!allowed) {
      // Client not in the allowlist — deny
      return false;
    }

    return allowed.has(audience);
  }
}
