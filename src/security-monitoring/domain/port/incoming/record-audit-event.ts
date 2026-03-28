// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface RecordAuditEventRequest {
  readonly eventType: string;
  readonly clientIdentifier: string;
  readonly sourceAddress: string;
  readonly details: Record<string, string>;
}

export type RecordAuditEventResponse =
  | { readonly recorded: true; readonly entryId: string }
  | { readonly recorded: false; readonly error: "audit_unavailable" | "invalid_event" };

export interface RecordAuditEvent {
  execute(request: RecordAuditEventRequest): Promise<RecordAuditEventResponse>;
}
