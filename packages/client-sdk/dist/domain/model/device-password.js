import { ok, err } from "./result.js";
const MIN_LENGTH = 8;
/**
 * Value object representing a device password used to seal/unseal the vault.
 * Distinct from the 2FApi passphrase/PIN — this protects local storage only.
 */
export class DevicePassword {
    value;
    constructor(value) {
        this.value = value;
    }
    static create(raw) {
        if (raw.length < MIN_LENGTH) {
            return err("Password must be at least 8 characters");
        }
        return ok(new DevicePassword(raw));
    }
    matches(confirmation) {
        return this.value === confirmation;
    }
}
//# sourceMappingURL=device-password.js.map