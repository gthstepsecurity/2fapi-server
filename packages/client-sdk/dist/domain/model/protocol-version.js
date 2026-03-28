/**
 * Value object for protocol version negotiation.
 * Ensures WASM module and server agree on transcript format.
 */
export class ProtocolVersion {
    major;
    minor;
    constructor(major, minor) {
        this.major = major;
        this.minor = minor;
    }
    static CURRENT = new ProtocolVersion(1, 0);
    static parse(version) {
        const match = version.match(/^(\d+)\.(\d+)$/);
        if (!match)
            return null;
        const major = parseInt(match[1], 10);
        if (major === 0)
            return null; // R1-12: reject version 0
        return new ProtocolVersion(major, parseInt(match[2], 10));
    }
    isCompatibleWith(other) {
        return this.major === other.major;
    }
    toString() {
        return `${this.major}.${this.minor}`;
    }
}
//# sourceMappingURL=protocol-version.js.map