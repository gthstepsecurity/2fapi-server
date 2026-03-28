// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuthenticationLevel } from "../../model/authentication-level.js";

export interface IssueTokenRequest {
  readonly clientIdentifier: string;
  readonly audience: string;
  readonly channelBindingHash: string;
  readonly authenticationLevel?: AuthenticationLevel;
  readonly verificationReceiptId?: string;
}

export type IssueTokenResponse =
  | {
      readonly success: true;
      readonly bearerToken: string;
      readonly expiresAtMs: number;
    }
  | {
      readonly success: false;
      readonly error: "issuance_refused";
    };

export interface IssueToken {
  execute(request: IssueTokenRequest): Promise<IssueTokenResponse>;
}
