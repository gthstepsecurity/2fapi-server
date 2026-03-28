// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RecoveryVerifier } from "../../../../src/client-registration/domain/service/recovery-verifier.js";
import type { Argon2Hasher, Argon2Params } from "../../../../src/client-registration/domain/port/outgoing/argon2-hasher.js";
import { RecoveryConfig } from "../../../../src/client-registration/domain/model/recovery-config.js";

function createStubArgon2Hasher(shouldMatch: boolean = true): Argon2Hasher {
  return {
    hash: async (input: Uint8Array, _salt: Uint8Array, _params: Argon2Params) => {
      // Use a simple deterministic "hash" for testing
      const result = new Uint8Array(32);
      for (let i = 0; i < Math.min(input.length, 32); i++) {
        result[i] = input[i]!;
      }
      return result;
    },
    verify: async (_input: Uint8Array, _salt: Uint8Array, _expected: Uint8Array, _params: Argon2Params) => {
      return shouldMatch;
    },
  };
}

describe("RecoveryVerifier", () => {
  const config = RecoveryConfig.defaults();

  it("derives salt as 'mnemonic' + clientIdentifier encoded as UTF-8", async () => {
    let capturedSalt: Uint8Array | null = null;
    const hasher: Argon2Hasher = {
      hash: async (_input: Uint8Array, salt: Uint8Array, _params: Argon2Params) => {
        capturedSalt = salt;
        return new Uint8Array(32);
      },
      verify: async (_input: Uint8Array, salt: Uint8Array, _expected: Uint8Array, _params: Argon2Params) => {
        capturedSalt = salt;
        return true;
      },
    };
    const verifier = new RecoveryVerifier(hasher);

    const storedHash = new Uint8Array(32);
    await verifier.verify(
      ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"],
      "alice-payment-service",
      storedHash,
      config,
    );

    const expectedSalt = new TextEncoder().encode("mnemonicalice-payment-service");
    expect(capturedSalt).toEqual(expectedSalt);
  });

  it("derives recovery key by concatenating words with spaces and encoding as UTF-8", async () => {
    let capturedInput: Uint8Array | null = null;
    const hasher: Argon2Hasher = {
      hash: async (input: Uint8Array, _salt: Uint8Array, _params: Argon2Params) => {
        capturedInput = input;
        return new Uint8Array(32);
      },
      verify: async (input: Uint8Array, _salt: Uint8Array, _expected: Uint8Array, _params: Argon2Params) => {
        capturedInput = input;
        return true;
      },
    };
    const verifier = new RecoveryVerifier(hasher);

    const words = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"];
    const storedHash = new Uint8Array(32);
    await verifier.verify(words, "alice-payment-service", storedHash, config);

    const expectedInput = new TextEncoder().encode(words.join(" "));
    expect(capturedInput).toEqual(expectedInput);
  });

  it("passes Argon2 params from recovery config to hasher", async () => {
    let capturedParams: Argon2Params | null = null;
    const hasher: Argon2Hasher = {
      hash: async (_input: Uint8Array, _salt: Uint8Array, params: Argon2Params) => {
        capturedParams = params;
        return new Uint8Array(32);
      },
      verify: async (_input: Uint8Array, _salt: Uint8Array, _expected: Uint8Array, params: Argon2Params) => {
        capturedParams = params;
        return true;
      },
    };
    const verifier = new RecoveryVerifier(hasher);

    const customConfig = RecoveryConfig.create({
      argon2Memory: 131072,
      argon2Iterations: 5,
      argon2Parallelism: 8,
    });

    await verifier.verify(
      ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"],
      "alice-payment-service",
      new Uint8Array(32),
      customConfig,
    );

    expect(capturedParams).toEqual({
      memory: 131072,
      iterations: 5,
      parallelism: 8,
      hashLength: 32,
    });
  });

  it("returns true when hasher.verify returns true", async () => {
    const hasher = createStubArgon2Hasher(true);
    const verifier = new RecoveryVerifier(hasher);

    const result = await verifier.verify(
      ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"],
      "alice-payment-service",
      new Uint8Array(32),
      config,
    );

    expect(result).toBe(true);
  });

  it("returns false when hasher.verify returns false", async () => {
    const hasher = createStubArgon2Hasher(false);
    const verifier = new RecoveryVerifier(hasher);

    const result = await verifier.verify(
      ["wrong", "words", "here", "not", "valid", "at", "all", "but", "twelve", "total", "needed", "now"],
      "alice-payment-service",
      new Uint8Array(32),
      config,
    );

    expect(result).toBe(false);
  });

  it("applies NFKD normalization to words before hashing (F06)", async () => {
    let capturedInput: Uint8Array | null = null;
    const hasher: Argon2Hasher = {
      hash: async (input: Uint8Array) => {
        capturedInput = input;
        return new Uint8Array(32);
      },
      verify: async (input: Uint8Array) => {
        capturedInput = input;
        return true;
      },
    };
    const verifier = new RecoveryVerifier(hasher);

    // U+00E9 (e-acute precomposed) → NFKD decomposes to e + combining acute
    const wordsWithAccent = ["caf\u00E9", "ability", "able", "about", "above", "absent",
      "absorb", "abstract", "absurd", "abuse", "access", "accident"];

    await verifier.verify(wordsWithAccent, "alice", new Uint8Array(32), config);

    // After NFKD normalization, "caf\u00E9" becomes "cafe\u0301"
    const expectedNormalized = wordsWithAccent.map(w => w.normalize("NFKD")).join(" ");
    expect(capturedInput).toEqual(new TextEncoder().encode(expectedNormalized));
  });

  it("deriveHash produces hash from words and client identifier", async () => {
    let capturedInput: Uint8Array | null = null;
    let capturedSalt: Uint8Array | null = null;
    const hasher: Argon2Hasher = {
      hash: async (input: Uint8Array, salt: Uint8Array, _params: Argon2Params) => {
        capturedInput = input;
        capturedSalt = salt;
        return new Uint8Array(32).fill(0xab);
      },
      verify: async () => true,
    };
    const verifier = new RecoveryVerifier(hasher);

    const words = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"];
    const result = await verifier.deriveHash(words, "alice-payment-service", config);

    expect(capturedInput).toEqual(new TextEncoder().encode(words.join(" ")));
    expect(capturedSalt).toEqual(new TextEncoder().encode("mnemonicalice-payment-service"));
    expect(result).toEqual(new Uint8Array(32).fill(0xab));
  });
});
