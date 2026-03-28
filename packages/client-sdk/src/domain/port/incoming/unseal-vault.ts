// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Result } from "../../model/result.js";
import type { DerivedSecret } from "../outgoing/crypto-engine.js";

/**
 * Driving port: unseal (decrypt) the vault to recover the derived secret.
 * Requires server cooperation (pepper delivery + attempt counter check).
 */
export interface UnsealVault {
  execute(request: UnsealVaultRequest): Promise<Result<UnsealVaultResponse, UnsealVaultError>>;
}

export interface UnsealVaultRequest {
  readonly password: string;
  readonly email: string;
  readonly tenantId: string;
  readonly clientId: string;
}

export interface UnsealVaultResponse {
  readonly secret: DerivedSecret;
  readonly attemptsRemaining: number;
}

export type UnsealVaultError =
  | "NO_VAULT_FOUND"
  | "VAULT_EXPIRED"
  | "VAULT_WIPED"
  | "WRONG_PASSWORD"
  | "SERVER_UNREACHABLE"
  | "VAULT_CORRUPTED";

export interface UnsealVaultFailureDetail {
  readonly error: UnsealVaultError;
  readonly attemptsRemaining?: number;
}
