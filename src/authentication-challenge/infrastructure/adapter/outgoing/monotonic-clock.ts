// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Clock } from "../../../domain/port/outgoing/clock.js";

export class MonotonicClock implements Clock {
  nowMs(): number {
    return Date.now();
  }
}
