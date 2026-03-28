// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface CredentialVerificationResult {
  readonly valid: boolean;
  readonly clientIdentifier: string;
  readonly clientStatus: "active" | "revoked" | "unknown";
  readonly isLegacyApiKey: boolean;
}

export interface CredentialVerifier {
  verify(clientIdentifier: string, credential: Uint8Array): Promise<CredentialVerificationResult>;
}
