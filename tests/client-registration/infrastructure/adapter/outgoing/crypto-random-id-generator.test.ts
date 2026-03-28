// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CryptoRandomIdGenerator } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/crypto-random-id-generator.js";

describe("CryptoRandomIdGenerator", () => {
  it("generates a ClientId with at least 16 bytes", () => {
    const generator = new CryptoRandomIdGenerator();

    const id = generator.generate();

    expect(id.toBytes().length).toBeGreaterThanOrEqual(16);
  });

  it("generates unique IDs on successive calls", () => {
    const generator = new CryptoRandomIdGenerator();

    const id1 = generator.generate();
    const id2 = generator.generate();

    expect(id1.equals(id2)).toBe(false);
  });

  it("generates IDs that can be represented as hex strings", () => {
    const generator = new CryptoRandomIdGenerator();

    const id = generator.generate();
    const hex = id.toString();

    expect(hex).toMatch(/^[0-9a-f]{32}$/);
  });
});
