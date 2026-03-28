import { ok } from "../../domain/model/result.js";
import { VaultPepper } from "../../domain/model/vault-pepper.js";
import { VaultAttemptCounter } from "../../domain/model/vault-attempt-counter.js";
/**
 * Server-side use case: generate a pepper for vault sealing.
 * Stores the pepper and initializes the attempt counter.
 */
export class HandleVaultSealUseCase {
    pepperStore;
    attemptStore;
    constructor(pepperStore, attemptStore) {
        this.pepperStore = pepperStore;
        this.attemptStore = attemptStore;
    }
    async execute(request) {
        // 1. Generate a fresh random pepper
        const pepper = VaultPepper.generate(request.clientId, request.deviceId);
        // 2. Store pepper (replaces any existing one for this device)
        await this.pepperStore.save(pepper);
        // 3. Initialize (or reset) the attempt counter
        const counter = VaultAttemptCounter.create(request.clientId, request.deviceId, request.threshold);
        await this.attemptStore.save(counter);
        return ok({
            pepper: pepper.valueForDerivation(),
            deviceId: request.deviceId,
        });
    }
    async deleteVault(clientId, deviceId) {
        await this.pepperStore.delete(clientId, deviceId);
        await this.attemptStore.delete(clientId, deviceId);
    }
}
//# sourceMappingURL=handle-vault-seal.js.map