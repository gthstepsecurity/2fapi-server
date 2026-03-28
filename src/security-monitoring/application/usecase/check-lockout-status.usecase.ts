// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CheckLockoutStatus,
  CheckLockoutStatusRequest,
  CheckLockoutStatusResponse,
} from "../../domain/port/incoming/check-lockout-status.js";
import type { AttemptCounterStore } from "../../domain/port/outgoing/attempt-counter-store.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import { FailedAttemptCounter } from "../../domain/model/failed-attempt-counter.js";
import { LockoutStatus } from "../../domain/model/lockout-status.js";
import { LockoutPolicy } from "../../domain/service/lockout-policy.js";

/**
 * Checks whether a client is currently locked out.
 * Does NOT disclose remaining lockout duration (NIST AAL2).
 */
export class CheckLockoutStatusUseCase implements CheckLockoutStatus {
  constructor(
    private readonly counterStore: AttemptCounterStore,
    private readonly lockoutPolicy: LockoutPolicy,
    private readonly clock: Clock,
  ) {}

  async execute(request: CheckLockoutStatusRequest): Promise<CheckLockoutStatusResponse> {
    const nowMs = this.clock.nowMs();
    const counter = await this.counterStore.findByClientIdentifier(request.clientIdentifier);

    if (counter === null) {
      return {
        status: LockoutStatus.unlocked(),
        consecutiveFailures: 0,
      };
    }

    const isLocked = this.lockoutPolicy.isLockedOut(counter, nowMs);

    return {
      status: isLocked
        ? LockoutStatus.locked(counter.lockedOutAtMs!)
        : LockoutStatus.unlocked(),
      consecutiveFailures: counter.consecutiveFailures,
    };
  }
}
