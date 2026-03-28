// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: ensures all traces are removed after a session ends.
 * Critical for shared devices (Tier 0) but applied to all tiers.
 */
export class SessionCleanup {
  constructor(
    private readonly zeroize: (buffer: Uint8Array) => void,
  ) {}

  /**
   * Execute the full cleanup checklist.
   * Best-effort: continues even if individual steps fail.
   */
  execute(params: CleanupParams): CleanupResult {
    const errors: string[] = [];

    // 1. Zeroize WASM-held buffers (R1-08 FIX: volatile read after fill)
    for (const buffer of params.wasmBuffers) {
      try {
        this.zeroize(buffer);
        // Force the compiler to keep the write (prevent dead store elimination)
        if (buffer.length > 0 && buffer[0] !== 0) {
          errors.push("zeroize_verification_failed");
        }
      } catch {
        errors.push("wasm_zeroize_failed");
      }
    }

    // 2. Null out JS references
    for (const ref of params.jsReferences) {
      try {
        ref.value = null;
      } catch {
        errors.push("js_nullify_failed");
      }
    }

    // 3. Clear session storage keys
    if (params.sessionStorage) {
      try {
        for (const key of params.sessionStorageKeys) {
          params.sessionStorage.removeItem(key);
        }
      } catch {
        errors.push("session_storage_clear_failed");
      }
    }

    // 4. Expire session cookie
    if (params.expireCookie) {
      try {
        params.expireCookie();
      } catch {
        errors.push("cookie_expire_failed");
      }
    }

    return {
      success: errors.length === 0,
      errors,
    };
  }
}

export interface CleanupParams {
  readonly wasmBuffers: Uint8Array[];
  readonly jsReferences: { value: unknown }[];
  readonly sessionStorage?: Storage;
  readonly sessionStorageKeys: string[];
  readonly expireCookie?: () => void;
}

export interface CleanupResult {
  readonly success: boolean;
  readonly errors: string[];
}
