import { VaultPepper } from "../../../domain/model/vault-pepper.js";
/**
 * PostgreSQL implementation of VaultPepperStore.
 * Stores vault peppers server-side per (client_id, device_id).
 */
export class PgVaultPepperStore {
    db;
    constructor(db) {
        this.db = db;
    }
    async save(pepper) {
        await this.db.query(`INSERT INTO vault_peppers (client_id, device_id, pepper)
       VALUES ($1, $2, $3)
       ON CONFLICT (client_id, device_id)
       DO UPDATE SET pepper = EXCLUDED.pepper, created_at = NOW()`, [pepper.clientId, pepper.deviceId, Buffer.from(pepper.value)]);
    }
    async findByDevice(clientId, deviceId) {
        const result = await this.db.query("SELECT client_id, device_id, pepper FROM vault_peppers WHERE client_id = $1 AND device_id = $2", [clientId, deviceId]);
        if (result.rows.length === 0)
            return null;
        const row = result.rows[0];
        return VaultPepper.restore(row.client_id, row.device_id, new Uint8Array(row.pepper), false);
    }
    async delete(clientId, deviceId) {
        await this.db.query("DELETE FROM vault_peppers WHERE client_id = $1 AND device_id = $2", [clientId, deviceId]);
    }
}
//# sourceMappingURL=pg-vault-pepper-store.js.map