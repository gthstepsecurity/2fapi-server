// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Audience } from "../../../../src/api-access-control/domain/model/audience.js";

describe("Audience", () => {
  it("creates from a non-empty string", () => {
    const aud = Audience.fromString("payment-service");
    expect(aud.value).toBe("payment-service");
  });

  it("rejects empty string", () => {
    expect(() => Audience.fromString("")).toThrow("Audience must not be empty");
  });

  it("rejects string longer than 256 characters", () => {
    const tooLong = "a".repeat(257);
    expect(() => Audience.fromString(tooLong)).toThrow(
      "Audience must not exceed 256 characters",
    );
  });

  it("accepts string of exactly 256 characters", () => {
    const maxLength = "a".repeat(256);
    const aud = Audience.fromString(maxLength);
    expect(aud.value).toBe(maxLength);
  });

  it("equals another Audience with same value", () => {
    const a = Audience.fromString("payment-service");
    const b = Audience.fromString("payment-service");
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal an Audience with different value", () => {
    const a = Audience.fromString("payment-service");
    const b = Audience.fromString("billing-service");
    expect(a.equals(b)).toBe(false);
  });
});
