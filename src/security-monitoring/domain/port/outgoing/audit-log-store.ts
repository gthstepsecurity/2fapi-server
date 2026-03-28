// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditEntry } from "../../model/audit-entry.js";

/**
 * Pagination options for findAll queries.
 * Prevents unbounded result sets in production.
 */
export interface FindAllOptions {
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Driven port for persisting audit log entries.
 * APPEND-ONLY for normal operations. Retention cleanup is allowed via deleteOlderThan.
 */
export interface AuditLogStore {
  append(entry: AuditEntry): Promise<void>;
  findAll(options?: FindAllOptions): Promise<readonly AuditEntry[]>;
  count(): Promise<number>;

  /**
   * CD03: Deletes audit entries older than the given timestamp.
   * Enables retention policy enforcement to prevent unbounded growth.
   * Returns the number of entries deleted.
   */
  deleteOlderThan(timestampMs: number): Promise<number>;

  /**
   * BG10: Returns recent entries within the specified time window.
   * More efficient than findAll() for anomaly detection — avoids O(N) full scan.
   */
  findRecent(sinceMs: number, limit: number): Promise<readonly AuditEntry[]>;
}
