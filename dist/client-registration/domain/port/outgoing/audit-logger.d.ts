export interface AuditEvent {
    eventType: string;
    clientIdentifier?: string;
    timestamp: Date;
    metadata?: Record<string, unknown>;
}
export interface AuditLogger {
    log(event: AuditEvent): Promise<void>;
}
//# sourceMappingURL=audit-logger.d.ts.map