// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenSigner } from "../../../domain/port/outgoing/token-signer.js";

/**
 * Stub token signer for testing.
 * Produces a deterministic "signature" by prepending a marker
 * byte to the payload. In production, EdDSA signing is used.
 */
export class StubTokenSigner implements TokenSigner {
  signCalls = 0;

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    this.signCalls++;
    // Signature = marker (0xSG) + payload
    const signed = new Uint8Array(payload.length + 2);
    signed[0] = 0x53; // 'S'
    signed[1] = 0x47; // 'G'
    signed.set(payload, 2);
    return signed;
  }
}
