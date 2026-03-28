// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogger, AuditEvent } from "../../../domain/port/outgoing/audit-logger.js";

// WARNING: This is a reference implementation. Production audit loggers MUST filter PII.

const SENSITIVE_FIELDS = new Set(["secret", "blinding", "proof"]);

function filterSensitiveMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!metadata) return metadata;
  const filtered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!SENSITIVE_FIELDS.has(key)) {
      filtered[key] = value;
    }
  }
  return filtered;
}

export class ConsoleAuditLogger implements AuditLogger {
  async log(event: AuditEvent): Promise<void> {
    const sanitized = {
      ...event,
      metadata: filterSensitiveMetadata(event.metadata),
    };
    console.log(JSON.stringify(sanitized));
  }
}
