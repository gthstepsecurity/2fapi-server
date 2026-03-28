// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Result } from "../../model/result.js";

/**
 * Driving port: full login flow with automatic tier detection and cascade.
 */
export interface Authenticate {
  execute(request: AuthRequest): Promise<Result<AuthResponse, AuthError>>;
}

export interface AuthRequest {
  readonly email: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly credential: string;
}

export interface AuthResponse {
  readonly jwt: string;
  readonly authTier: 0 | 1 | 2;
  readonly expiresAtMs: number;
}

export type AuthError =
  | "WRONG_CREDENTIAL"
  | "VAULT_WIPED"
  | "SERVER_UNREACHABLE"
  | "WASM_NOT_AVAILABLE"
  | "ACCOUNT_LOCKED";
