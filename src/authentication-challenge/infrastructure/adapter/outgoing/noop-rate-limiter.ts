// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { RateLimiter } from "../../../domain/port/outgoing/rate-limiter.js";

export class NoopRateLimiter implements RateLimiter {
  async isAllowed(): Promise<boolean> {
    return true;
  }
}
