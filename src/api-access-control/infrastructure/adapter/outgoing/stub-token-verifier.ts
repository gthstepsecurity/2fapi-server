// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenVerifier } from "../../../domain/port/outgoing/token-verifier.js";

/**
 * Stub token verifier for testing.
 * Checks for the marker bytes from StubTokenSigner and returns payload.
 * Can be configured to always fail for testing error paths.
 */
export class StubTokenVerifier implements TokenVerifier {
  verifyCalls = 0;

  constructor(private shouldSucceed: boolean = true) {}

  async verify(signedToken: Uint8Array): Promise<Uint8Array | null> {
    this.verifyCalls++;
    if (!this.shouldSucceed) {
      return null;
    }
    // Check for StubTokenSigner marker
    if (signedToken.length < 2 || signedToken[0] !== 0x53 || signedToken[1] !== 0x47) {
      return null;
    }
    return signedToken.slice(2);
  }

  setResult(shouldSucceed: boolean): void {
    this.shouldSucceed = shouldSucceed;
  }
}
