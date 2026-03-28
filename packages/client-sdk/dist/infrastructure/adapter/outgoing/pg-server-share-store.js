/**
 * PostgreSQL adapter for server secret share storage (R31).
 */
export class PgServerShareStore {
    db;
    constructor(db) {
        this.db = db;
    }
    async save(tenantId, clientId, shareS, shareR, partialCommitment) {
        await this.db.query(`INSERT INTO server_secret_shares (tenant_id, client_id, share_s, share_r, partial_commitment)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, client_id)
       DO UPDATE SET share_s = EXCLUDED.share_s, share_r = EXCLUDED.share_r,
         partial_commitment = EXCLUDED.partial_commitment, rotated_at = NOW()`, [tenantId, clientId, Buffer.from(shareS), Buffer.from(shareR), Buffer.from(partialCommitment)]);
    }
    async findByClient(tenantId, clientId) {
        const result = await this.db.query("SELECT share_s, share_r FROM server_secret_shares WHERE tenant_id = $1 AND client_id = $2", [tenantId, clientId]);
        if (result.rows.length === 0)
            return null;
        const row = result.rows[0];
        return {
            shareS: new Uint8Array(row.share_s),
            shareR: new Uint8Array(row.share_r),
        };
    }
    async delete(tenantId, clientId) {
        await this.db.query("DELETE FROM server_secret_shares WHERE tenant_id = $1 AND client_id = $2", [tenantId, clientId]);
    }
}
//# sourceMappingURL=pg-server-share-store.js.map