// WARNING: This is a reference implementation. Production audit loggers MUST filter PII.
const SENSITIVE_FIELDS = new Set(["secret", "blinding", "proof"]);
function filterSensitiveMetadata(metadata) {
    if (!metadata)
        return metadata;
    const filtered = {};
    for (const [key, value] of Object.entries(metadata)) {
        if (!SENSITIVE_FIELDS.has(key)) {
            filtered[key] = value;
        }
    }
    return filtered;
}
export class ConsoleAuditLogger {
    async log(event) {
        const sanitized = {
            ...event,
            metadata: filterSensitiveMetadata(event.metadata),
        };
        console.log(JSON.stringify(sanitized));
    }
}
//# sourceMappingURL=console-audit-logger.js.map