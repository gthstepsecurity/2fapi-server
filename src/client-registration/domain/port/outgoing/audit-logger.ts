// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface AuditEvent {
  eventType: string;
  clientIdentifier?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export interface AuditLogger {
  log(event: AuditEvent): Promise<void>;
}
