// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenInvalidator } from "../../../../client-registration/domain/port/outgoing/token-invalidator.js";

/**
 * No-op token invalidator for production use.
 *
 * Tokens are short-lived JWTs that expire naturally via their `exp` claim.
 * There is no server-side token store to invalidate against. When a client
 * is revoked, the ClientStatusChecker denies access on the next token
 * validation, making explicit token invalidation unnecessary.
 *
 * If a token blacklist is added in the future, this adapter should be
 * replaced with one that writes to the blacklist store.
 */
export class NoopTokenInvalidator implements TokenInvalidator {
  async invalidateAllForClient(_clientIdentifier: string): Promise<void> {
    // Tokens expire naturally via TTL; no server-side store to invalidate.
    // ClientStatusChecker enforces revocation at validation time.
  }
}
