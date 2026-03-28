// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { HedgedNonceGenerator } from "../../src/zk-verification/infrastructure/adapter/outgoing/hedged-nonce-generator.js";

describe("C-04: Empty secretContext in HedgedNonceGenerator", () => {
  it("throws when secretContext is empty string", () => {
    expect(() => new HedgedNonceGenerator("")).toThrow();
  });

  it("accepts non-empty secretContext", () => {
    expect(() => new HedgedNonceGenerator("valid-secret")).not.toThrow();
  });
});
