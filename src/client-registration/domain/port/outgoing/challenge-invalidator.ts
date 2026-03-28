// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Anti-corruption layer port for invalidating pending challenges
 * when a client is revoked or its commitment is rotated.
 *
 * Implementation lives in infrastructure and communicates with
 * the Authentication Challenge bounded context via integration events.
 */
export interface ChallengeInvalidator {
  invalidateAllForClient(clientIdentifier: string): Promise<void>;
}
