const EXPIRY_WARNING_HOURS = 12;
const STORAGE_KEY_PREFIX = "2fapi-vault:";
/**
 * Value object representing an encrypted vault stored in localStorage.
 * Contains only the ciphertext and metadata — never the plaintext secret.
 */
export class VaultEntry {
    iv;
    ciphertext;
    tag;
    deviceId;
    createdAtMs;
    maxTtlHours;
    version;
    constructor(params) {
        this.iv = params.iv;
        this.ciphertext = params.ciphertext;
        this.tag = params.tag;
        this.deviceId = params.deviceId;
        this.createdAtMs = params.createdAtMs;
        this.maxTtlHours = params.maxTtlHours;
        this.version = params.version;
    }
    static create(params) {
        return new VaultEntry(params);
    }
    isExpired(nowMs) {
        const expiresAtMs = this.createdAtMs + this.maxTtlHours * 60 * 60 * 1000;
        return nowMs >= expiresAtMs;
    }
    remainingHours(nowMs) {
        const expiresAtMs = this.createdAtMs + this.maxTtlHours * 60 * 60 * 1000;
        const remainingMs = expiresAtMs - nowMs;
        return Math.max(0, Math.floor(remainingMs / (60 * 60 * 1000)));
    }
    isApproachingExpiry(nowMs) {
        const remaining = this.remainingHours(nowMs);
        return remaining > 0 && remaining < EXPIRY_WARNING_HOURS;
    }
    storageKey(email) {
        return `${STORAGE_KEY_PREFIX}${email}`;
    }
    serialize() {
        return {
            iv: toBase64(this.iv),
            ciphertext: toBase64(this.ciphertext),
            tag: toBase64(this.tag),
            deviceId: this.deviceId,
            createdAtMs: this.createdAtMs,
            maxTtlHours: this.maxTtlHours,
            version: this.version,
        };
    }
    static deserialize(data) {
        return new VaultEntry({
            iv: fromBase64(data.iv),
            ciphertext: fromBase64(data.ciphertext),
            tag: fromBase64(data.tag),
            deviceId: data.deviceId,
            createdAtMs: data.createdAtMs,
            maxTtlHours: data.maxTtlHours,
            version: data.version,
        });
    }
}
function toBase64(bytes) {
    return Buffer.from(bytes).toString("base64");
}
function fromBase64(str) {
    return new Uint8Array(Buffer.from(str, "base64"));
}
//# sourceMappingURL=vault-entry.js.map