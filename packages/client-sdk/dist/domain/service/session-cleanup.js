/**
 * Domain service: ensures all traces are removed after a session ends.
 * Critical for shared devices (Tier 0) but applied to all tiers.
 */
export class SessionCleanup {
    zeroize;
    constructor(zeroize) {
        this.zeroize = zeroize;
    }
    /**
     * Execute the full cleanup checklist.
     * Best-effort: continues even if individual steps fail.
     */
    execute(params) {
        const errors = [];
        // 1. Zeroize WASM-held buffers (R1-08 FIX: volatile read after fill)
        for (const buffer of params.wasmBuffers) {
            try {
                this.zeroize(buffer);
                // Force the compiler to keep the write (prevent dead store elimination)
                if (buffer.length > 0 && buffer[0] !== 0) {
                    errors.push("zeroize_verification_failed");
                }
            }
            catch {
                errors.push("wasm_zeroize_failed");
            }
        }
        // 2. Null out JS references
        for (const ref of params.jsReferences) {
            try {
                ref.value = null;
            }
            catch {
                errors.push("js_nullify_failed");
            }
        }
        // 3. Clear session storage keys
        if (params.sessionStorage) {
            try {
                for (const key of params.sessionStorageKeys) {
                    params.sessionStorage.removeItem(key);
                }
            }
            catch {
                errors.push("session_storage_clear_failed");
            }
        }
        // 4. Expire session cookie
        if (params.expireCookie) {
            try {
                params.expireCookie();
            }
            catch {
                errors.push("cookie_expire_failed");
            }
        }
        return {
            success: errors.length === 0,
            errors,
        };
    }
}
//# sourceMappingURL=session-cleanup.js.map