// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  AuthenticationLevel,
  STANDARD_TTL_MS,
  ELEVATED_TTL_MS,
  ttlForLevel,
} from "../../../../src/api-access-control/domain/model/authentication-level.js";

describe("AuthenticationLevel", () => {
  it("STANDARD has value 'standard'", () => {
    expect(AuthenticationLevel.STANDARD).toBe("standard");
  });

  it("ELEVATED has value 'elevated'", () => {
    expect(AuthenticationLevel.ELEVATED).toBe("elevated");
  });

  it("standard TTL is 15 minutes in milliseconds", () => {
    expect(STANDARD_TTL_MS).toBe(15 * 60 * 1000);
  });

  it("elevated TTL is 5 minutes in milliseconds", () => {
    expect(ELEVATED_TTL_MS).toBe(5 * 60 * 1000);
  });

  it("ttlForLevel returns standard TTL for standard level", () => {
    expect(ttlForLevel(AuthenticationLevel.STANDARD)).toBe(STANDARD_TTL_MS);
  });

  it("ttlForLevel returns elevated TTL for elevated level", () => {
    expect(ttlForLevel(AuthenticationLevel.ELEVATED)).toBe(ELEVATED_TTL_MS);
  });
});
