const MIN_BYTE_LENGTH = 16;
export class ClientId {
    bytes;
    constructor(bytes) {
        this.bytes = new Uint8Array(bytes);
    }
    static fromBytes(bytes) {
        if (bytes.length < MIN_BYTE_LENGTH) {
            throw new Error(`ClientId must be at least 16 bytes, got ${bytes.length}`);
        }
        return new ClientId(bytes);
    }
    toBytes() {
        return new Uint8Array(this.bytes);
    }
    equals(other) {
        if (this.bytes.length !== other.bytes.length)
            return false;
        for (let i = 0; i < this.bytes.length; i++) {
            if (this.bytes[i] !== other.bytes[i])
                return false;
        }
        return true;
    }
    toString() {
        return Array.from(this.bytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }
}
//# sourceMappingURL=client-id.js.map