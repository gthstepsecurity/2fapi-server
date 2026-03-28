import { ok, err } from "../../domain/model/result.js";
import { VaultAttemptCounter } from "../../domain/model/vault-attempt-counter.js";
/**
 * Server-side use case: validate an unseal attempt and deliver the pepper.
 * - Checks the attempt counter
 * - If under threshold: delivers the pepper
 * - If wiped: destroys the pepper permanently and returns "wiped"
 */
export class HandleVaultUnsealAttemptUseCase {
    pepperStore;
    attemptStore;
    constructor(pepperStore, attemptStore) {
        this.pepperStore = pepperStore;
        this.attemptStore = attemptStore;
    }
    async execute(params) {
        // 1. Check attempt counter first (wipe state persists even after pepper destruction)
        const counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
        if (counter?.isWiped) {
            // Ensure pepper is destroyed (idempotent)
            await this.pepperStore.delete(params.clientId, params.deviceId);
            return ok({ status: "wiped" });
        }
        // 2. Check pepper exists
        const pepper = await this.pepperStore.findByDevice(params.clientId, params.deviceId);
        if (!pepper) {
            return err("NO_VAULT_REGISTERED");
        }
        // 3. Create counter if first attempt
        if (!counter) {
            const newCounter = VaultAttemptCounter.create(params.clientId, params.deviceId);
            await this.attemptStore.save(newCounter);
            return ok({
                status: "allowed",
                pepper: pepper.valueForDerivation(),
                attemptsRemaining: newCounter.attemptsRemaining,
            });
        }
        // 4. Deliver pepper
        return ok({
            status: "allowed",
            pepper: pepper.valueForDerivation(),
            attemptsRemaining: counter.attemptsRemaining,
        });
    }
    async reportFailure(params) {
        let counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
        if (!counter) {
            counter = VaultAttemptCounter.create(params.clientId, params.deviceId);
        }
        const updated = counter.recordFailure();
        await this.attemptStore.save(updated);
        // Destroy pepper if wipe triggered
        if (updated.isWiped) {
            await this.pepperStore.delete(params.clientId, params.deviceId);
        }
    }
    async reportSuccess(params) {
        const counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
        if (!counter)
            return;
        const reset = counter.recordSuccess();
        await this.attemptStore.save(reset);
    }
}
//# sourceMappingURL=handle-vault-unseal-attempt.js.map