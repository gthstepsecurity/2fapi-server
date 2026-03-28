// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultAttemptCounter } from "../../model/vault-attempt-counter.js";

/**
 * Server-side port: persists vault unseal attempt counters per device.
 */
export interface VaultAttemptStore {
  findByDevice(clientId: string, deviceId: string): Promise<VaultAttemptCounter | null>;
  save(counter: VaultAttemptCounter): Promise<void>;
  delete(clientId: string, deviceId: string): Promise<void>;
}
