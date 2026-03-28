import { randomBytes } from "node:crypto";
const KEY_LENGTH = 32;
/**
 * Immutable value object representing a server-side OPRF key.
 * The key is a random 256-bit scalar used for blind evaluation.
 * Stored only on the server — never sent to the client.
 */
export class OprfKey {
    clientId;
    deviceId;
    value;
    isDestroyed;
    constructor(clientId, deviceId, value, isDestroyed) {
        this.clientId = clientId;
        this.deviceId = deviceId;
        this.value = value;
        this.isDestroyed = isDestroyed;
    }
    static generate(clientId, deviceId) {
        const bytes = new Uint8Array(randomBytes(KEY_LENGTH));
        return new OprfKey(clientId, deviceId, bytes, false);
    }
    static restore(clientId, deviceId, value, isDestroyed) {
        return new OprfKey(clientId, deviceId, value, isDestroyed);
    }
    valueForEvaluation() {
        if (this.isDestroyed) {
            throw new Error("OPRF key has been destroyed");
        }
        return this.value;
    }
    destroy() {
        const zeroed = new Uint8Array(KEY_LENGTH);
        return new OprfKey(this.clientId, this.deviceId, zeroed, true);
    }
}
//# sourceMappingURL=oprf-key.js.map