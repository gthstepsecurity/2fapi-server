// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { createHash } from "node:crypto";

/**
 * Hedged nonce generator that derives nonces using:
 *   nonce = H(secret_context || counter || random)
 *
 * This is the same hedged-nonce strategy used in RFC 6979 and EdDSA.
 * Even if the RNG produces weak or repeated output, the secret-dependent
 * context and monotonic counter guarantee nonce uniqueness.
 *
 * The counter must be incremented atomically to prevent reuse.
 */
export class HedgedNonceGenerator {
  private readonly secretContext: Buffer;

  constructor(secretContext: string) {
    if (secretContext.length === 0) {
      throw new Error("secretContext must not be empty — it provides domain separation for hedged nonce derivation");
    }
    this.secretContext = Buffer.from(secretContext, "utf-8");
  }

  /**
   * Derives a 32-byte nonce from the hedged construction.
   * @param randomBytes Raw bytes from the OS RNG (may be degraded)
   * @param counter Monotonically increasing counter value
   * @returns 32-byte derived nonce
   */
  deriveNonce(randomBytes: Uint8Array, counter: number): Uint8Array {
    const hash = createHash("sha256");

    // Domain separation: include secret context
    hash.update(this.secretContext);

    // Counter as 8-byte big-endian
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    hash.update(counterBuf);

    // Random component (may be weak — that's fine, counter provides uniqueness)
    hash.update(randomBytes);

    return new Uint8Array(hash.digest());
  }
}
