import { ok, err } from "../../domain/model/result.js";
export class UnsealVaultUseCase {
    crypto;
    server;
    localStore;
    constructor(crypto, server, localStore) {
        this.crypto = crypto;
        this.server = server;
        this.localStore = localStore;
    }
    async execute(request) {
        // 1. Check vault exists locally
        const entry = this.localStore.load(request.email);
        if (!entry) {
            return err("NO_VAULT_FOUND");
        }
        // 2. Check TTL
        if (entry.isExpired(Date.now())) {
            this.localStore.delete(request.email);
            return err("VAULT_EXPIRED");
        }
        // 3. Request pepper from server (also validates attempt counter)
        let pepper;
        let attemptsRemaining;
        try {
            const response = await this.server.requestUnseal({
                clientId: request.clientId,
                deviceId: entry.deviceId,
            });
            if (response.status === "wiped") {
                this.localStore.delete(request.email);
                return err("VAULT_WIPED");
            }
            if (response.status === "vault_expired") {
                this.localStore.delete(request.email);
                return err("VAULT_EXPIRED");
            }
            pepper = response.pepper;
            attemptsRemaining = response.attemptsRemaining;
        }
        catch {
            return err("SERVER_UNREACHABLE");
        }
        // 4. Derive vault key from password + pepper
        let vaultKey;
        try {
            vaultKey = await this.crypto.deriveVaultKey(request.password, pepper, entry.deviceId, request.email, request.tenantId);
        }
        finally {
            // Always zeroize pepper after use
            this.crypto.zeroize(pepper);
        }
        // 5. Decrypt vault
        try {
            const plaintext = await this.crypto.decrypt(vaultKey, {
                iv: entry.iv,
                ciphertext: entry.ciphertext,
                tag: entry.tag,
            });
            // 6. Extract secret and blinding from plaintext
            const secret = {
                secret: plaintext.slice(0, 32),
                blinding: plaintext.slice(32, 64),
            };
            // Zeroize plaintext
            this.crypto.zeroize(plaintext);
            return ok({ secret, attemptsRemaining });
        }
        catch {
            // GCM tag mismatch = wrong password
            await this.server.reportUnsealFailure({
                clientId: request.clientId,
                deviceId: entry.deviceId,
            }).catch(() => { }); // best-effort
            return err("WRONG_PASSWORD");
        }
        finally {
            // Always zeroize vault key
            this.crypto.zeroize(vaultKey);
        }
    }
}
//# sourceMappingURL=unseal-vault.js.map