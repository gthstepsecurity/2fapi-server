// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for hardware-bound key derivation via WebAuthn PRF extension.
 * The PRF produces a deterministic 256-bit key bound to:
 * - The specific hardware (TPM / Secure Enclave)
 * - The WebAuthn credential ID
 * - A salt provided by the application
 *
 * The key never leaves the hardware. Requires biometric/PIN per access.
 */
export interface HardwareKeyStore {
  /**
   * Check if the WebAuthn PRF extension is supported on this device.
   */
  isPrfSupported(): Promise<boolean>;

  /**
   * Derive a hardware-bound key via WebAuthn PRF.
   * Requires biometric verification.
   * Returns 32 bytes (256-bit key).
   */
  deriveKey(params: HardwareKeyParams): Promise<HardwareKeyResult>;
}

export interface HardwareKeyParams {
  readonly email: string;
  readonly rpId: string;
  readonly salt: string;
}

export type HardwareKeyResult =
  | { readonly status: "ok"; readonly hwKey: Uint8Array }
  | { readonly status: "cancelled" }
  | { readonly status: "not_supported" }
  | { readonly status: "error"; readonly message: string };
