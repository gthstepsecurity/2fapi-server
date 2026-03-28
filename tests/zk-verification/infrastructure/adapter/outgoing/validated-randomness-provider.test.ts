// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  ValidatedRandomnessProvider,
  type RandomBytesSource,
} from "../../../../../src/zk-verification/infrastructure/adapter/outgoing/validated-randomness-provider.js";

function createFixedSource(bytes: Uint8Array): RandomBytesSource {
  return { generateRandomBytes: () => bytes };
}

function createGoodSource(): RandomBytesSource {
  return {
    generateRandomBytes: (length: number) => {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        bytes[i] = (i * 37 + 13) % 256;
      }
      return bytes;
    },
  };
}

describe("ValidatedRandomnessProvider (E05)", () => {
  it("returns random bytes from a healthy source", () => {
    const provider = new ValidatedRandomnessProvider(createGoodSource());
    const result = provider.generateValidatedRandomBytes(32);
    expect(result.length).toBe(32);
  });

  it("rejects all-zero output", () => {
    const provider = new ValidatedRandomnessProvider(
      createFixedSource(new Uint8Array(32)),
    );
    expect(() => provider.generateValidatedRandomBytes(32)).toThrow(
      "all-zero output",
    );
  });

  it("rejects constant-byte output", () => {
    const provider = new ValidatedRandomnessProvider(
      createFixedSource(new Uint8Array(32).fill(0xab)),
    );
    expect(() => provider.generateValidatedRandomBytes(32)).toThrow(
      "constant-byte output",
    );
  });

  it("rejects low-diversity output", () => {
    // Only 3 unique bytes in 32 bytes
    const lowDiversity = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      lowDiversity[i] = i % 3;
    }
    const provider = new ValidatedRandomnessProvider(
      createFixedSource(lowDiversity),
    );
    expect(() => provider.generateValidatedRandomBytes(32)).toThrow(
      "insufficient diversity",
    );
  });

  it("rejects wrong-length output", () => {
    const provider = new ValidatedRandomnessProvider({
      generateRandomBytes: () => new Uint8Array(16),
    });
    expect(() => provider.generateValidatedRandomBytes(32)).toThrow(
      "requested 32 bytes, got 16",
    );
  });

  it("rejects zero-length request", () => {
    const provider = new ValidatedRandomnessProvider(createGoodSource());
    expect(() => provider.generateValidatedRandomBytes(0)).toThrow("positive");
  });
});
