// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  RecordFailedAttempt,
  RecordFailedAttemptRequest,
  RecordFailedAttemptResponse,
} from "../../domain/port/incoming/record-failed-attempt.js";
import type { AttemptCounterStore } from "../../domain/port/outgoing/attempt-counter-store.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import { FailedAttemptCounter } from "../../domain/model/failed-attempt-counter.js";
import { LockoutPolicy } from "../../domain/service/lockout-policy.js";
import { ClientLockedOut } from "../../domain/event/client-locked-out.js";

/**
 * Increments the failed attempt counter for a client.
 * Publishes ClientLockedOut event when threshold is reached.
 */
export class RecordFailedAttemptUseCase implements RecordFailedAttempt {
  constructor(
    private readonly counterStore: AttemptCounterStore,
    private readonly lockoutPolicy: LockoutPolicy,
    private readonly eventPublisher: EventPublisher,
    private readonly clock: Clock,
  ) {}

  async execute(request: RecordFailedAttemptRequest): Promise<RecordFailedAttemptResponse> {
    const nowMs = this.clock.nowMs();
    const existing = await this.counterStore.findByClientIdentifier(request.clientIdentifier);
    const current = existing ?? FailedAttemptCounter.create(request.clientIdentifier);

    const updated = current.increment(nowMs, this.lockoutPolicy.lockoutConfig);
    await this.counterStore.save(updated);

    const lockedOut = this.lockoutPolicy.shouldLockOut(updated);

    if (lockedOut && !this.lockoutPolicy.shouldLockOut(current)) {
      await this.eventPublisher.publish(
        new ClientLockedOut(
          request.clientIdentifier,
          nowMs,
          updated.consecutiveFailures,
        ),
      );
    }

    return {
      recorded: true,
      lockedOut,
      consecutiveFailures: updated.consecutiveFailures,
    };
  }
}
