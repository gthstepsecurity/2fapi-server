// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeInvalidator } from "../../../domain/port/outgoing/challenge-invalidator.js";

export class StubChallengeInvalidator implements ChallengeInvalidator {
  readonly invalidatedClients: string[] = [];

  async invalidateAllForClient(clientIdentifier: string): Promise<void> {
    this.invalidatedClients.push(clientIdentifier);
  }
}
