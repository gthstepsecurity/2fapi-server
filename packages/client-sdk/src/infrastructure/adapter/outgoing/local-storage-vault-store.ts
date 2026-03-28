// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VaultLocalStore } from "../../../domain/port/outgoing/vault-local-store.js";
import { VaultEntry } from "../../../domain/model/vault-entry.js";

const KEY_PREFIX = "2fapi-vault:";

/**
 * Infrastructure adapter: stores encrypted vault entries in localStorage.
 * Implements the VaultLocalStore driven port.
 */
export class LocalStorageVaultStore implements VaultLocalStore {
  constructor(private readonly storage: Storage) {}

  save(email: string, entry: VaultEntry): void {
    const key = `${KEY_PREFIX}${email}`;
    const json = JSON.stringify(entry.serialize());
    this.storage.setItem(key, json);
  }

  load(email: string): VaultEntry | null {
    const key = `${KEY_PREFIX}${email}`;
    const raw = this.storage.getItem(key);
    if (!raw) return null;

    try {
      const data = JSON.parse(raw);
      return VaultEntry.deserialize(data);
    } catch {
      return null;
    }
  }

  delete(email: string): void {
    const key = `${KEY_PREFIX}${email}`;
    this.storage.removeItem(key);
  }

  exists(email: string): boolean {
    const key = `${KEY_PREFIX}${email}`;
    return this.storage.getItem(key) !== null;
  }
}
