// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Anti-corruption layer port to lookup a client's current status
 * from the Client Registration bounded context.
 * Returns null if the client is unknown.
 */
export interface ClientStatusLookup {
  getStatus(clientIdentifier: string): Promise<"active" | "suspended" | "revoked" | null>;
}
