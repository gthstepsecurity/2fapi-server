// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Argon2Hasher, Argon2Params } from "../port/outgoing/argon2-hasher.js";
import type { RecoveryConfig } from "../model/recovery-config.js";

/**
 * Domain service that verifies recovery phrases against stored hashes.
 * Derives salt = "mnemonic" + clientIdentifier (BIP-39 convention),
 * concatenates words with spaces, encodes as UTF-8, and delegates to Argon2Hasher.
 */
export class RecoveryVerifier {
  private static readonly SALT_PREFIX = "mnemonic";

  constructor(private readonly argon2Hasher: Argon2Hasher) {}

  /**
   * Verifies that the provided words match the stored hash.
   */
  async verify(
    words: readonly string[],
    clientIdentifier: string,
    storedHash: Uint8Array,
    config: RecoveryConfig,
  ): Promise<boolean> {
    const input = this.deriveInput(words);
    const salt = this.deriveSalt(clientIdentifier);
    const params = this.toArgon2Params(config);

    return this.argon2Hasher.verify(input, salt, storedHash, params);
  }

  /**
   * Derives the Argon2id hash from words and client identifier.
   * Used during enrollment to generate the hash for storage.
   */
  async deriveHash(
    words: readonly string[],
    clientIdentifier: string,
    config: RecoveryConfig,
  ): Promise<Uint8Array> {
    const input = this.deriveInput(words);
    const salt = this.deriveSalt(clientIdentifier);
    const params = this.toArgon2Params(config);

    return this.argon2Hasher.hash(input, salt, params);
  }

  private deriveInput(words: readonly string[]): Uint8Array {
    // F06: Apply NFKD normalization (BIP-39 standard requirement) before hashing
    const normalizedWords = words.map((w) => w.normalize("NFKD"));
    return new TextEncoder().encode(normalizedWords.join(" "));
  }

  private deriveSalt(clientIdentifier: string): Uint8Array {
    return new TextEncoder().encode(
      RecoveryVerifier.SALT_PREFIX + clientIdentifier,
    );
  }

  private toArgon2Params(config: RecoveryConfig): Argon2Params {
    return {
      memory: config.argon2Memory,
      iterations: config.argon2Iterations,
      parallelism: config.argon2Parallelism,
      hashLength: 32,
    };
  }
}
