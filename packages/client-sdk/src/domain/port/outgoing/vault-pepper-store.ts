// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultPepper } from "../../model/vault-pepper.js";

/**
 * Server-side port: stores vault peppers per (clientId, deviceId).
 * Implemented by a database adapter (PostgreSQL, Redis, etc.).
 */
export interface VaultPepperStore {
  save(pepper: VaultPepper): Promise<void>;
  findByDevice(clientId: string, deviceId: string): Promise<VaultPepper | null>;
  delete(clientId: string, deviceId: string): Promise<void>;
}
