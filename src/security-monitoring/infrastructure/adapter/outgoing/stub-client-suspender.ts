// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientSuspender } from "../../../domain/port/outgoing/client-suspender.js";
import type { SuspensionReasonValue } from "../../../domain/model/suspension-reason.js";

/**
 * Stub implementation of ClientSuspender for testing.
 * Records all suspension calls for assertions.
 */
export class StubClientSuspender implements ClientSuspender {
  readonly suspensions: Array<{ clientIdentifier: string; reason: SuspensionReasonValue }> = [];
  private alreadySuspended = false;

  async suspend(clientIdentifier: string, reason: SuspensionReasonValue): Promise<boolean> {
    this.suspensions.push({ clientIdentifier, reason });
    return !this.alreadySuspended;
  }

  /** Test helper: simulate client already being suspended. */
  setAlreadySuspended(value: boolean): void {
    this.alreadySuspended = value;
  }
}
