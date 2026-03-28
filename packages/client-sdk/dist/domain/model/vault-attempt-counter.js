const DEFAULT_THRESHOLD = 3;
const MIN_THRESHOLD = 3;
/**
 * Immutable value object tracking vault unseal attempts per device.
 * Lives server-side — the client cannot modify this.
 *
 * Wipe is permanent: once wiped, the pepper is destroyed and the vault
 * can never be unsealed again (the device must re-enroll).
 */
export class VaultAttemptCounter {
    clientId;
    deviceId;
    consecutiveFailures;
    isWiped;
    threshold;
    constructor(clientId, deviceId, consecutiveFailures, isWiped, threshold) {
        this.clientId = clientId;
        this.deviceId = deviceId;
        this.consecutiveFailures = consecutiveFailures;
        this.isWiped = isWiped;
        this.threshold = threshold;
    }
    static create(clientId, deviceId, threshold = DEFAULT_THRESHOLD) {
        const effectiveThreshold = normalizeThreshold(threshold);
        return new VaultAttemptCounter(clientId, deviceId, 0, false, effectiveThreshold);
    }
    static restore(clientId, deviceId, consecutiveFailures, isWiped, threshold) {
        return new VaultAttemptCounter(clientId, deviceId, consecutiveFailures, isWiped, threshold);
    }
    get attemptsRemaining() {
        if (this.isWiped || this.threshold === 0)
            return 0;
        return Math.max(0, this.threshold - this.consecutiveFailures);
    }
    recordFailure() {
        if (this.isWiped)
            return this;
        const newCount = this.consecutiveFailures + 1;
        const wiped = this.threshold > 0 && newCount >= this.threshold;
        return new VaultAttemptCounter(this.clientId, this.deviceId, newCount, wiped, this.threshold);
    }
    recordSuccess() {
        if (this.isWiped)
            return this; // wipe is permanent
        return new VaultAttemptCounter(this.clientId, this.deviceId, 0, false, this.threshold);
    }
}
function normalizeThreshold(threshold) {
    if (threshold === 0)
        return 0; // disabled
    return Math.max(MIN_THRESHOLD, threshold);
}
//# sourceMappingURL=vault-attempt-counter.js.map