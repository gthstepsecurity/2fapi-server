// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Anti-corruption layer for the Client Registration bounded context.
 * Looks up a client's stored commitment and status.
 */
export interface CommitmentInfo {
  readonly commitment: Uint8Array;
  readonly clientStatus: "active" | "revoked" | "unknown";
}

export interface CommitmentLookup {
  findByClientIdentifier(clientIdentifier: string): Promise<CommitmentInfo | null>;
}
