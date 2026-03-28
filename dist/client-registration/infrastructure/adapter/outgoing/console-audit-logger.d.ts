import type { AuditLogger, AuditEvent } from "../../../domain/port/outgoing/audit-logger.js";
export declare class ConsoleAuditLogger implements AuditLogger {
    log(event: AuditEvent): Promise<void>;
}
//# sourceMappingURL=console-audit-logger.d.ts.map