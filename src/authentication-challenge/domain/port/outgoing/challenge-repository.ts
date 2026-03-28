// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Challenge } from "../../model/challenge.js";
import type { ChallengeId } from "../../model/challenge-id.js";

export interface ChallengeRepository {
  save(challenge: Challenge): Promise<void>;
  findById(id: ChallengeId): Promise<Challenge | null>;
  findPendingByClientIdentifier(clientIdentifier: string): Promise<Challenge | null>;
  delete(id: ChallengeId): Promise<void>;
  deleteExpiredBefore(nowMs: number): Promise<number>;
  capacityPercentage(): Promise<number>;
}
