// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenInvalidator } from "../../../domain/port/outgoing/token-invalidator.js";

export class StubTokenInvalidator implements TokenInvalidator {
  readonly invalidatedClients: string[] = [];

  async invalidateAllForClient(clientIdentifier: string): Promise<void> {
    this.invalidatedClients.push(clientIdentifier);
  }
}
