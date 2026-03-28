// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultEntry } from "../../model/vault-entry.js";

/**
 * Port for local vault persistence (localStorage adapter).
 * Stores only encrypted blobs — never plaintext secrets.
 */
export interface VaultLocalStore {
  /**
   * Save an encrypted vault entry for a specific email.
   * Throws QuotaExceededError if localStorage is full.
   */
  save(email: string, entry: VaultEntry): void;

  /**
   * Load the encrypted vault entry for a specific email.
   * Returns null if no vault exists for this email.
   */
  load(email: string): VaultEntry | null;

  /**
   * Delete the vault entry for a specific email.
   */
  delete(email: string): void;

  /**
   * Check if a vault exists for a specific email.
   */
  exists(email: string): boolean;
}
