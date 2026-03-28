import { randomBytes } from "node:crypto";
const PEPPER_LENGTH = 32;
/**
 * Immutable value object representing a server-side vault pepper.
 * The pepper is a random 256-bit value that is:
 * - Generated during vault seal
 * - Stored only on the server (per client_id + device_id)
 * - Delivered to the SDK only during a validated unseal attempt
 * - Permanently destroyed on wipe (making the vault undecryptable)
 */
export class VaultPepper {
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
        const bytes = new Uint8Array(randomBytes(PEPPER_LENGTH));
        return new VaultPepper(clientId, deviceId, bytes, false);
    }
    static restore(clientId, deviceId, value, isDestroyed) {
        return new VaultPepper(clientId, deviceId, value, isDestroyed);
    }
    /**
     * Returns the pepper value for use in key derivation.
     * Throws if the pepper has been destroyed (wipe scenario).
     */
    valueForDerivation() {
        if (this.isDestroyed) {
            throw new Error("Pepper has been destroyed");
        }
        return this.value;
    }
    /**
     * Destroy the pepper permanently. Returns a new instance with zeroed value.
     * This is irreversible — the vault becomes permanently undecryptable.
     */
    destroy() {
        const zeroed = new Uint8Array(PEPPER_LENGTH);
        return new VaultPepper(this.clientId, this.deviceId, zeroed, true);
    }
}
//# sourceMappingURL=vault-pepper.js.map