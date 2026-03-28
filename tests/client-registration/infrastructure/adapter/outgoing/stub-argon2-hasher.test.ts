// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { StubArgon2Hasher } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";

describe("StubArgon2Hasher", () => {
  const params = { memory: 65536, iterations: 3, parallelism: 4, hashLength: 32 };

  it("hash produces a 32-byte output", async () => {
    const hasher = new StubArgon2Hasher();

    const input = new TextEncoder().encode("test-input");
    const salt = new TextEncoder().encode("test-salt");
    const result = await hasher.hash(input, salt, params);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("hash is deterministic: same input+salt produces same output", async () => {
    const hasher = new StubArgon2Hasher();

    const input = new TextEncoder().encode("test-input");
    const salt = new TextEncoder().encode("test-salt");
    const result1 = await hasher.hash(input, salt, params);
    const result2 = await hasher.hash(input, salt, params);

    expect(result1).toEqual(result2);
  });

  it("hash produces different output for different inputs", async () => {
    const hasher = new StubArgon2Hasher();

    const salt = new TextEncoder().encode("test-salt");
    const result1 = await hasher.hash(new TextEncoder().encode("input-a"), salt, params);
    const result2 = await hasher.hash(new TextEncoder().encode("input-b"), salt, params);

    expect(result1).not.toEqual(result2);
  });

  it("hash produces different output for different salts", async () => {
    const hasher = new StubArgon2Hasher();

    const input = new TextEncoder().encode("test-input");
    const result1 = await hasher.hash(input, new TextEncoder().encode("salt-a"), params);
    const result2 = await hasher.hash(input, new TextEncoder().encode("salt-b"), params);

    expect(result1).not.toEqual(result2);
  });

  it("verify returns true when input+salt matches expected", async () => {
    const hasher = new StubArgon2Hasher();

    const input = new TextEncoder().encode("test-input");
    const salt = new TextEncoder().encode("test-salt");
    const hash = await hasher.hash(input, salt, params);
    const result = await hasher.verify(input, salt, hash, params);

    expect(result).toBe(true);
  });

  it("verify returns false when input does not match", async () => {
    const hasher = new StubArgon2Hasher();

    const salt = new TextEncoder().encode("test-salt");
    const hash = await hasher.hash(new TextEncoder().encode("correct-input"), salt, params);
    const result = await hasher.verify(new TextEncoder().encode("wrong-input"), salt, hash, params);

    expect(result).toBe(false);
  });
});
