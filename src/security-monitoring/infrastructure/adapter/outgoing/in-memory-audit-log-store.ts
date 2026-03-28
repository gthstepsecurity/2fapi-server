// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogStore, FindAllOptions } from "../../../domain/port/outgoing/audit-log-store.js";
import type { AuditEntry } from "../../../domain/model/audit-entry.js";

const DEFAULT_LIMIT = 1000;

/**
 * In-memory reference implementation of AuditLogStore.
 * APPEND-ONLY: entries cannot be modified or deleted.
 * Entries are frozen at creation (AuditEntry enforces this).
 * For testing and development only.
 */
export class InMemoryAuditLogStore implements AuditLogStore {
  private readonly entries: AuditEntry[] = [];
  private unavailable = false;

  async append(entry: AuditEntry): Promise<void> {
    if (this.unavailable) {
      throw new Error("Audit log store is unavailable");
    }
    this.entries.push(entry);
  }

  async findAll(options?: FindAllOptions): Promise<readonly AuditEntry[]> {
    if (this.unavailable) {
      throw new Error("Audit log store is unavailable");
    }
    const limit = options?.limit ?? DEFAULT_LIMIT;
    const offset = options?.offset ?? 0;
    return this.entries.slice(offset, offset + limit);
  }

  async count(): Promise<number> {
    return this.entries.length;
  }

  async deleteOlderThan(timestampMs: number): Promise<number> {
    const before = this.entries.length;
    const remaining = this.entries.filter((e) => e.timestampMs >= timestampMs);
    this.entries.length = 0;
    this.entries.push(...remaining);
    return before - remaining.length;
  }

  async findRecent(sinceMs: number, limit: number): Promise<readonly AuditEntry[]> {
    if (this.unavailable) {
      throw new Error("Audit log store is unavailable");
    }
    return this.entries
      .filter((e) => e.timestampMs >= sinceMs)
      .slice(0, limit);
  }

  /** Test helper: simulate store unavailability. */
  setUnavailable(unavailable: boolean): void {
    this.unavailable = unavailable;
  }
}
