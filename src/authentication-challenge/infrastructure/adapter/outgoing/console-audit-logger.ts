// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogger, AuditEntry } from "../../../domain/port/outgoing/audit-logger.js";

export class ConsoleAuditLogger implements AuditLogger {
  async log(entry: AuditEntry): Promise<void> {
    const sanitized = { ...entry.details };
    // Remove sensitive fields from audit output
    delete sanitized["credential"];
    delete sanitized["secret"];
    delete sanitized["nonce"];

    console.log(
      `[AUDIT] ${entry.timestamp.toISOString()} | ${entry.action} | client=${entry.clientIdentifier} | ${JSON.stringify(sanitized)}`,
    );
  }
}
