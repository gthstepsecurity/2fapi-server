// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuthenticationLevel } from "../../model/authentication-level.js";

export interface ValidateTokenRequest {
  readonly bearerToken: string;
  readonly channelBindingHash: string;
  readonly expectedAudience: string;
}

export type ValidateTokenResponse =
  | {
      readonly success: true;
      readonly clientIdentifier: string;
      readonly audience: string;
      readonly level: AuthenticationLevel;
    }
  | {
      readonly success: false;
      readonly error: "access_denied";
    };

export interface ValidateToken {
  execute(request: ValidateTokenRequest): Promise<ValidateTokenResponse>;
}
