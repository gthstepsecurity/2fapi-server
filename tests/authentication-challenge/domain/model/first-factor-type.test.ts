// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { FirstFactorType } from "../../../../src/authentication-challenge/domain/model/first-factor-type.js";

describe("FirstFactorType", () => {
  it("should represent a zero-knowledge proof first factor", () => {
    expect(FirstFactorType.ZKP).toBe("zkp");
  });

  it("should represent a legacy API key first factor", () => {
    expect(FirstFactorType.LEGACY_API_KEY).toBe("legacy-api-key");
  });
});
