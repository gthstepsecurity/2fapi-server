// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";
import type { NonceGenerator } from "../../../domain/port/outgoing/nonce-generator.js";
import { Nonce } from "../../../domain/model/nonce.js";

const U64_MAX = BigInt("18446744073709551615");
const RANDOM_BYTES_LENGTH = 16;

/**
 * In-memory reference implementation of NonceGenerator.
 *
 * Known limitation: the monotonic counter restarts at 0 on each new instance
 * (e.g., process restart). This is acceptable because each nonce includes a
 * 128-bit CSPRNG random part, making collision probability negligible (2^-128)
 * even with counter restart. For production deployments requiring persistent
 * counter state, implement a durable NonceGenerator adapter backed by
 * persistent storage.
 */
export class CryptoNonceGenerator implements NonceGenerator {
  private counter: bigint;

  constructor(initialCounter: bigint = BigInt(0)) {
    this.counter = initialCounter;
  }

  generate(): Nonce {
    if (this.counter >= U64_MAX) {
      throw new Error("Nonce generator counter exhaustion: monotonic counter has reached u64 max");
    }
    const randomPart = randomBytes(RANDOM_BYTES_LENGTH);
    const nonce = Nonce.create(new Uint8Array(randomPart), this.counter);
    this.counter += BigInt(1);
    return nonce;
  }
}
