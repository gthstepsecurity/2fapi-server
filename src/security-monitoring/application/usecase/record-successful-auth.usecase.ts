// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  RecordSuccessfulAuth,
  RecordSuccessfulAuthRequest,
  RecordSuccessfulAuthResponse,
} from "../../domain/port/incoming/record-successful-auth.js";
import type { AttemptCounterStore } from "../../domain/port/outgoing/attempt-counter-store.js";
import { FailedAttemptCounter } from "../../domain/model/failed-attempt-counter.js";

/**
 * Records a successful authentication, decrementing the failure counter by 1.
 * BE08: Uses recordSuccess() instead of reset() to prevent lockout evasion
 * via success alternation (N-1 failures + 1 success pattern).
 */
export class RecordSuccessfulAuthUseCase implements RecordSuccessfulAuth {
  constructor(
    private readonly counterStore: AttemptCounterStore,
  ) {}

  async execute(request: RecordSuccessfulAuthRequest): Promise<RecordSuccessfulAuthResponse> {
    const existing = await this.counterStore.findByClientIdentifier(request.clientIdentifier);
    const current = existing ?? FailedAttemptCounter.create(request.clientIdentifier);
    const updated = current.recordSuccess();
    await this.counterStore.save(updated);
    return { recorded: true };
  }
}
