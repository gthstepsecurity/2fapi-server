// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";

/**
 * Integration tests for RealArgon2Hasher.
 *
 * Requires: argon2 npm package
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("RealArgon2Hasher [integration]", () => {
  it("should hash and verify a value", async () => {
    const { RealArgon2Hasher } = await import(
      "../../../src/client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js"
    );

    const hasher = new RealArgon2Hasher();
    const input = new TextEncoder().encode("correct horse battery staple");
    const salt = new Uint8Array(16).fill(0x42);
    const params = { memory: 4096, iterations: 1, parallelism: 1, hashLength: 32 };

    const hash = await hasher.hash(input, salt, params);
    expect(hash).toHaveLength(32);

    const isValid = await hasher.verify(input, salt, hash, params);
    expect(isValid).toBe(true);
  });

  it("should reject wrong input", async () => {
    const { RealArgon2Hasher } = await import(
      "../../../src/client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js"
    );

    const hasher = new RealArgon2Hasher();
    const correct = new TextEncoder().encode("correct");
    const wrong = new TextEncoder().encode("wrong");
    const salt = new Uint8Array(16).fill(0x42);
    const params = { memory: 4096, iterations: 1, parallelism: 1, hashLength: 32 };

    const hash = await hasher.hash(correct, salt, params);

    const isValid = await hasher.verify(wrong, salt, hash, params);
    expect(isValid).toBe(false);
  });

  it("should produce different hashes for different salts", async () => {
    const { RealArgon2Hasher } = await import(
      "../../../src/client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js"
    );

    const hasher = new RealArgon2Hasher();
    const input = new TextEncoder().encode("same input");
    const salt1 = new Uint8Array(16).fill(0x01);
    const salt2 = new Uint8Array(16).fill(0x02);
    const params = { memory: 4096, iterations: 1, parallelism: 1, hashLength: 32 };

    const hash1 = await hasher.hash(input, salt1, params);
    const hash2 = await hasher.hash(input, salt2, params);

    // Different salts should produce different hashes
    let same = true;
    for (let i = 0; i < hash1.length; i++) {
      if (hash1[i] !== hash2[i]) {
        same = false;
        break;
      }
    }
    expect(same).toBe(false);
  });
});
