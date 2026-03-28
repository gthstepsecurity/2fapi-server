// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface AuditEntry {
  readonly action: string;
  readonly clientIdentifier: string;
  readonly timestamp: Date;
  readonly details: Record<string, unknown>;
}

export interface AuditLogger {
  log(entry: AuditEntry): Promise<void>;
}
