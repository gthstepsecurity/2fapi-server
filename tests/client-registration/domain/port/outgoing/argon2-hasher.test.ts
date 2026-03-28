// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import type { Argon2Hasher, Argon2Params } from "../../../../../src/client-registration/domain/port/outgoing/argon2-hasher.js";

describe("Argon2Hasher port", () => {
  const defaultParams: Argon2Params = {
    memory: 65536,
    iterations: 3,
    parallelism: 4,
    hashLength: 32,
  };

  it("defines hash method returning Uint8Array", async () => {
    const hasher: Argon2Hasher = {
      hash: async () => new Uint8Array(32).fill(0xab),
      verify: async () => true,
    };

    const input = new TextEncoder().encode("test-input");
    const salt = new TextEncoder().encode("test-salt");
    const result = await hasher.hash(input, salt, defaultParams);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("defines verify method returning true on match", async () => {
    const hasher: Argon2Hasher = {
      hash: async () => new Uint8Array(32).fill(0xab),
      verify: async () => true,
    };

    const input = new TextEncoder().encode("test-input");
    const salt = new TextEncoder().encode("test-salt");
    const expected = new Uint8Array(32).fill(0xab);
    const result = await hasher.verify(input, salt, expected, defaultParams);

    expect(result).toBe(true);
  });

  it("defines verify method returning false on mismatch", async () => {
    const hasher: Argon2Hasher = {
      hash: async () => new Uint8Array(32).fill(0xab),
      verify: async () => false,
    };

    const input = new TextEncoder().encode("wrong-input");
    const salt = new TextEncoder().encode("test-salt");
    const expected = new Uint8Array(32).fill(0xab);
    const result = await hasher.verify(input, salt, expected, defaultParams);

    expect(result).toBe(false);
  });
});
