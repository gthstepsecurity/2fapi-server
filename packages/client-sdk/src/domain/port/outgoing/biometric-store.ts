// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for biometric credential storage via WebAuthn Credential Manager.
 * The secret (s, r) is stored as the credential's userHandle (64 bytes).
 * Requires biometric verification (fingerprint/face) for each retrieval.
 */
export interface BiometricStore {
  /**
   * Check if the platform supports biometric authentication (WebAuthn PRF).
   */
  isAvailable(): Promise<boolean>;

  /**
   * Check if a biometric credential exists for this email.
   */
  hasCredential(email: string): Promise<boolean>;

  /**
   * Store the derived secret behind biometric authentication.
   * Creates a WebAuthn credential with the PRF extension.
   */
  store(params: BiometricStoreParams): Promise<BiometricStoreResult>;

  /**
   * Retrieve the derived secret via biometric authentication.
   */
  retrieve(email: string, rpId: string): Promise<BiometricRetrieveResult>;

  /**
   * Delete the biometric credential for an email.
   */
  delete(email: string): Promise<void>;
}

export interface BiometricStoreParams {
  readonly email: string;
  readonly clientId: string;
  readonly rpId: string;
  readonly secret: Uint8Array;
  readonly blinding: Uint8Array;
}

export interface BiometricStoreResult {
  readonly credentialId: string;
  readonly prfSupported: boolean;
}

export type BiometricRetrieveResult =
  | { readonly status: "ok"; readonly secret: Uint8Array; readonly blinding: Uint8Array; readonly hwKey?: Uint8Array }
  | { readonly status: "cancelled" }
  | { readonly status: "not_found" }
  | { readonly status: "error"; readonly message: string };
