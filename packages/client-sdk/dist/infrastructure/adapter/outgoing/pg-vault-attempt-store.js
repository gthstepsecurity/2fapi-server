import { VaultAttemptCounter } from "../../../domain/model/vault-attempt-counter.js";
/**
 * PostgreSQL implementation of VaultAttemptStore.
 * Uses UPSERT for atomic create/update of attempt counters.
 */
export class PgVaultAttemptStore {
    db;
    constructor(db) {
        this.db = db;
    }
    async findByDevice(clientId, deviceId) {
        const result = await this.db.query(`SELECT client_id, device_id, consecutive_failures, is_wiped, threshold
       FROM vault_attempt_counters
       WHERE client_id = $1 AND device_id = $2`, [clientId, deviceId]);
        if (result.rows.length === 0)
            return null;
        const row = result.rows[0];
        return VaultAttemptCounter.restore(row.client_id, row.device_id, row.consecutive_failures, row.is_wiped, row.threshold);
    }
    async save(counter) {
        await this.db.query(`INSERT INTO vault_attempt_counters (client_id, device_id, consecutive_failures, is_wiped, threshold, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (client_id, device_id)
       DO UPDATE SET
         consecutive_failures = EXCLUDED.consecutive_failures,
         is_wiped = EXCLUDED.is_wiped,
         threshold = EXCLUDED.threshold,
         updated_at = NOW()`, [counter.clientId, counter.deviceId, counter.consecutiveFailures, counter.isWiped, counter.threshold]);
    }
    async delete(clientId, deviceId) {
        await this.db.query("DELETE FROM vault_attempt_counters WHERE client_id = $1 AND device_id = $2", [clientId, deviceId]);
    }
}
//# sourceMappingURL=pg-vault-attempt-store.js.map