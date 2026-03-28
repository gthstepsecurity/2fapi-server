// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeConsumer, ChallengeInfo } from "../../../domain/port/outgoing/challenge-consumer.js";

export class StubChallengeConsumer implements ChallengeConsumer {
  readonly consumedChallengeIds: string[] = [];

  constructor(private result: ChallengeInfo | null = null) {}

  async consumeIfValid(challengeId: string): Promise<ChallengeInfo | null> {
    this.consumedChallengeIds.push(challengeId);
    return this.result;
  }

  setResult(result: ChallengeInfo | null): void {
    this.result = result;
  }
}
