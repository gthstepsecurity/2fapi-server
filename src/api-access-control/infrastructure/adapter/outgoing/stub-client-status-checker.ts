// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientStatusChecker } from "../../../domain/port/outgoing/client-status-checker.js";

export class StubClientStatusChecker implements ClientStatusChecker {
  checkCalls: string[] = [];

  constructor(private active: boolean = true) {}

  async isActive(clientIdentifier: string): Promise<boolean> {
    this.checkCalls.push(clientIdentifier);
    return this.active;
  }

  setActive(active: boolean): void {
    this.active = active;
  }
}
