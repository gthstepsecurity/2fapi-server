// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DevicePassword } from "../../../../packages/client-sdk/src/domain/model/device-password.js";

describe("DevicePassword", () => {
  it("accepts a password of 8 or more characters", () => {
    const result = DevicePassword.create("MyD3v!ce");
    expect(result.isOk()).toBe(true);
  });

  it("rejects a password shorter than 8 characters", () => {
    const result = DevicePassword.create("abc");
    expect(result.isErr()).toBe(true);
    expect(result.unwrapErr()).toBe("Password must be at least 8 characters");
  });

  it("rejects an empty password", () => {
    const result = DevicePassword.create("");
    expect(result.isErr()).toBe(true);
  });

  it("accepts exactly 8 characters", () => {
    const result = DevicePassword.create("12345678");
    expect(result.isOk()).toBe(true);
  });

  it("exposes the value for derivation", () => {
    const password = DevicePassword.create("MyD3v!ceP@ss").unwrap();
    expect(password.value).toBe("MyD3v!ceP@ss");
  });

  it("confirms matching passwords", () => {
    const password = DevicePassword.create("MyD3v!ceP@ss").unwrap();
    expect(password.matches("MyD3v!ceP@ss")).toBe(true);
  });

  it("rejects mismatched confirmation", () => {
    const password = DevicePassword.create("MyD3v!ceP@ss").unwrap();
    expect(password.matches("MyD3v!cePAss")).toBe(false);
  });
});
