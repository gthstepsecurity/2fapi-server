// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CredentialVerifier,
  CredentialVerificationResult,
} from "../../../domain/port/outgoing/credential-verifier.js";

export class StubCredentialVerifier implements CredentialVerifier {
  constructor(private readonly result: CredentialVerificationResult) {}

  async verify(): Promise<CredentialVerificationResult> {
    return this.result;
  }
}
