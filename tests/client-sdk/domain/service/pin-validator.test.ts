// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PinValidator } from "../../../../packages/client-sdk/src/domain/service/pin-validator.js";

describe("PinValidator", () => {
  const validator = new PinValidator();

  it("accepts a valid 6-digit PIN", () => {
    const result = validator.validate("847291");
    expect(result.isOk()).toBe(true);
  });

  it("rejects a PIN shorter than 6 digits", () => {
    const result = validator.validate("8472");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PIN must be 6 digits");
  });

  it("rejects a PIN longer than 6 digits", () => {
    const result = validator.validate("8472910");
    expect(result.isErr()).toBe(true);
  });

  it("rejects non-numeric characters", () => {
    const result = validator.validate("abc123");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PIN must contain only digits");
  });

  it("rejects all same digits with specific error message", () => {
    const result = validator.validate("111111");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PIN must not be all the same digit");
  });

  it("warns on sequential PIN 123456 but does not block", () => {
    const result = validator.validate("123456");
    expect(result.isOk()).toBe(true);
    // Warning should be available separately
    expect(validator.isWeak("123456")).toBe(true);
  });

  it("accepts PIN with leading zeros", () => {
    const result = validator.validate("007842");
    expect(result.isOk()).toBe(true);
  });

  it("preserves leading zeros", () => {
    const result = validator.validate("007842");
    expect(result.unwrap()).toBe("007842");
  });

  it("rejects empty input", () => {
    const result = validator.validate("");
    expect(result.isErr()).toBe(true);
  });

  it("rejects a PIN with leading non-digit character", () => {
    const result = validator.validate("a12345");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PIN must contain only digits");
  });

  it("rejects a PIN with trailing non-digit character", () => {
    const result = validator.validate("12345a");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("PIN must contain only digits");
  });

  it("filters non-numeric from raw input", () => {
    const filtered = validator.filterNumeric("abc123def456");
    expect(filtered).toBe("123456");
  });

  it("reports weak PINs", () => {
    expect(validator.isWeak("123456")).toBe(true);
    expect(validator.isWeak("654321")).toBe(true);
    expect(validator.isWeak("000000")).toBe(true);
    expect(validator.isWeak("847291")).toBe(false);
  });
});
