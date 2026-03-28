// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { createHash } from "node:crypto";
import type { Argon2Hasher, Argon2Params } from "../../../domain/port/outgoing/argon2-hasher.js";

/**
 * Stub Argon2 hasher that uses SHA-256 instead of real Argon2id.
 * Suitable for testing environments only — NOT for production use.
 *
 * The hash is computed as: SHA-256(salt || input), truncated/padded to hashLength.
 * This provides deterministic, fast hashing for tests without requiring
 * the Argon2 native library.
 */
export class StubArgon2Hasher implements Argon2Hasher {
  async hash(input: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
    return this.computeHash(input, salt, params.hashLength);
  }

  async verify(
    input: Uint8Array,
    salt: Uint8Array,
    expected: Uint8Array,
    params: Argon2Params,
  ): Promise<boolean> {
    const computed = this.computeHash(input, salt, params.hashLength);
    if (computed.length !== expected.length) return false;
    // Constant-time comparison for test correctness
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed[i]! ^ expected[i]!;
    }
    return diff === 0;
  }

  private computeHash(input: Uint8Array, salt: Uint8Array, hashLength: number): Uint8Array {
    const hash = createHash("sha256");
    hash.update(salt);
    hash.update(input);
    const digest = hash.digest();
    return new Uint8Array(digest.buffer, digest.byteOffset, Math.min(digest.length, hashLength));
  }
}
