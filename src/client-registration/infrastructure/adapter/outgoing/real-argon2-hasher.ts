// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Argon2Hasher, Argon2Params } from "../../../domain/port/outgoing/argon2-hasher.js";

/**
 * Real Argon2id implementation of the Argon2Hasher port.
 *
 * Uses the `argon2` npm package which wraps the reference C implementation.
 * Always uses the Argon2id variant (hybrid of Argon2i and Argon2d),
 * which provides resistance to both side-channel and GPU attacks.
 *
 * This adapter is for PRODUCTION use only. Tests should use StubArgon2Hasher
 * which substitutes SHA-256 for speed.
 *
 * Security properties:
 * - Memory-hard: configurable memory cost (default 64 MB)
 * - Time-hard: configurable iteration count
 * - Parallelism: configurable thread count
 * - Argon2id variant: recommended by OWASP and RFC 9106
 *
 * @requires argon2 — installed at runtime, dynamically imported
 */
export class RealArgon2Hasher implements Argon2Hasher {
  async hash(input: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
    const argon2 = await import("argon2");
    const result = await argon2.hash(Buffer.from(input), {
      type: argon2.argon2id,
      salt: Buffer.from(salt),
      memoryCost: params.memory,
      timeCost: params.iterations,
      parallelism: params.parallelism,
      hashLength: params.hashLength,
      raw: true,
    });

    return new Uint8Array(result);
  }

  async verify(
    input: Uint8Array,
    salt: Uint8Array,
    expected: Uint8Array,
    params: Argon2Params,
  ): Promise<boolean> {
    const computed = await this.hash(input, salt, params);

    // Constant-time comparison to prevent timing attacks
    if (computed.length !== expected.length) {
      return false;
    }

    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed[i]! ^ expected[i]!;
    }
    return diff === 0;
  }
}
