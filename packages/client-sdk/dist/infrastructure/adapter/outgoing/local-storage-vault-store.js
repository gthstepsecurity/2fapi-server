import { VaultEntry } from "../../../domain/model/vault-entry.js";
const KEY_PREFIX = "2fapi-vault:";
/**
 * Infrastructure adapter: stores encrypted vault entries in localStorage.
 * Implements the VaultLocalStore driven port.
 */
export class LocalStorageVaultStore {
    storage;
    constructor(storage) {
        this.storage = storage;
    }
    save(email, entry) {
        const key = `${KEY_PREFIX}${email}`;
        const json = JSON.stringify(entry.serialize());
        this.storage.setItem(key, json);
    }
    load(email) {
        const key = `${KEY_PREFIX}${email}`;
        const raw = this.storage.getItem(key);
        if (!raw)
            return null;
        try {
            const data = JSON.parse(raw);
            return VaultEntry.deserialize(data);
        }
        catch {
            return null;
        }
    }
    delete(email) {
        const key = `${KEY_PREFIX}${email}`;
        this.storage.removeItem(key);
    }
    exists(email) {
        const key = `${KEY_PREFIX}${email}`;
        return this.storage.getItem(key) !== null;
    }
}
//# sourceMappingURL=local-storage-vault-store.js.map