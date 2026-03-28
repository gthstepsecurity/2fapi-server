import { ok, err } from "../../domain/model/result.js";
import { DevicePassword } from "../../domain/model/device-password.js";
import { VaultEntry } from "../../domain/model/vault-entry.js";
const DEFAULT_TTL_HOURS = 72;
const VAULT_VERSION = 1;
export class SealVaultUseCase {
    crypto;
    server;
    localStore;
    constructor(crypto, server, localStore) {
        this.crypto = crypto;
        this.server = server;
        this.localStore = localStore;
    }
    async execute(request) {
        // 1. Validate password
        const passwordResult = DevicePassword.create(request.password);
        if (passwordResult.isErr()) {
            return err("PASSWORD_TOO_SHORT");
        }
        const password = passwordResult.unwrap();
        if (!password.matches(request.passwordConfirmation)) {
            return err("PASSWORDS_DO_NOT_MATCH");
        }
        // 2. Request pepper from server
        let pepper;
        let deviceId;
        try {
            const sealResponse = await this.server.requestSeal({
                clientId: request.clientId,
                deviceId: request.deviceId,
            });
            pepper = sealResponse.pepper;
            deviceId = sealResponse.deviceId;
        }
        catch {
            return err("SERVER_UNREACHABLE");
        }
        try {
            // 3. Derive vault key from password + pepper
            const vaultKey = await this.crypto.deriveVaultKey(password.value, pepper, deviceId, request.email, request.tenantId);
            // 4. Zeroize pepper immediately after key derivation
            this.crypto.zeroize(pepper);
            // 5. Encrypt the secret material
            const plaintext = new Uint8Array(64);
            plaintext.set(request.secret, 0);
            plaintext.set(request.blinding, 32);
            const encrypted = await this.crypto.encrypt(vaultKey, plaintext);
            // 6. Zeroize vault key and plaintext
            this.crypto.zeroize(vaultKey);
            this.crypto.zeroize(plaintext);
            // 7. Store encrypted vault locally
            const entry = VaultEntry.create({
                iv: encrypted.iv,
                ciphertext: encrypted.ciphertext,
                tag: encrypted.tag,
                deviceId,
                createdAtMs: Date.now(),
                maxTtlHours: DEFAULT_TTL_HOURS,
                version: VAULT_VERSION,
            });
            this.localStore.save(request.email, entry);
            return ok({ deviceId });
        }
        catch {
            // Ensure pepper is zeroized even on error
            this.crypto.zeroize(pepper);
            return err("CRYPTO_UNAVAILABLE");
        }
    }
}
//# sourceMappingURL=seal-vault.js.map