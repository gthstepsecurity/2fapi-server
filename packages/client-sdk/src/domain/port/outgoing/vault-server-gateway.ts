// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Port for server-side vault operations.
 * The server holds the pepper and the attempt counter.
 */
export interface VaultServerGateway {
  /**
   * Request a new pepper for vault sealing.
   * Server generates a random 256-bit pepper and stores it per (clientId, deviceId).
   */
  requestSeal(params: SealRequest): Promise<SealResponse>;

  /**
   * Request permission to unseal and receive the pepper.
   * Server checks the attempt counter and delivers the pepper only if under threshold.
   */
  requestUnseal(params: UnsealRequest): Promise<UnsealResponse>;

  /**
   * Notify the server that an unseal attempt failed (wrong password).
   * Server increments the failure counter.
   */
  reportUnsealFailure(params: UnsealFailureReport): Promise<void>;

  /**
   * Notify the server that authentication succeeded (reset counter).
   */
  reportAuthSuccess(params: AuthSuccessReport): Promise<void>;

  /**
   * Notify the server to delete the vault registration (user removed vault).
   */
  deleteVaultRegistration(clientId: string, deviceId: string): Promise<void>;
}

export interface SealRequest {
  readonly clientId: string;
  readonly deviceId: string;
}

export interface SealResponse {
  readonly pepper: Uint8Array;
  readonly deviceId: string;
}

export interface UnsealRequest {
  readonly clientId: string;
  readonly deviceId: string;
}

export type UnsealResponse =
  | { readonly status: "allowed"; readonly pepper: Uint8Array; readonly attemptsRemaining: number }
  | { readonly status: "wiped" }
  | { readonly status: "vault_expired" };

export interface UnsealFailureReport {
  readonly clientId: string;
  readonly deviceId: string;
}

export interface AuthSuccessReport {
  readonly clientId: string;
  readonly deviceId: string;
}
