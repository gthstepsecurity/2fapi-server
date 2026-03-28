// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { sanitizeRedisKey } from "../../src/api-gateway/validation.js";

describe("I-04: Redis key injection prevention via sanitizeRedisKey", () => {
  it("preserves valid alphanumeric keys", () => {
    expect(sanitizeRedisKey("alice-payment.service_v2")).toBe("alice-payment.service_v2");
  });

  it("strips spaces", () => {
    expect(sanitizeRedisKey("alice service")).toBe("aliceservice");
  });

  it("strips semicolons and colons", () => {
    expect(sanitizeRedisKey("alice;DROP:TABLE")).toBe("aliceDROPTABLE");
  });

  it("strips newlines and carriage returns", () => {
    expect(sanitizeRedisKey("alice\nservice\r")).toBe("aliceservice");
  });

  it("strips glob/wildcard characters", () => {
    expect(sanitizeRedisKey("alice*service?[a]")).toBe("aliceservicea");
  });

  it("returns empty string for all-special input", () => {
    expect(sanitizeRedisKey("***;;;")).toBe("");
  });

  it("handles empty string", () => {
    expect(sanitizeRedisKey("")).toBe("");
  });
});
