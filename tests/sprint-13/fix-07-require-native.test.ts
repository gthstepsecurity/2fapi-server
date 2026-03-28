// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import {
  requireNative,
  setNativeConstantTimeModule,
  resetNativeConstantTimeModule,
} from "../../src/shared/constant-time.js";

describe("FIX 7 — requireNative()", () => {
  beforeEach(() => {
    resetNativeConstantTimeModule();
  });

  it("throws when native module is not loaded", () => {
    expect(() => requireNative()).toThrow(
      "Native constant-time module is required",
    );
  });

  it("does not throw when native module is loaded", () => {
    const fakeModule = {
      constantTimeEq: () => true,
    };
    setNativeConstantTimeModule(fakeModule);

    expect(() => requireNative()).not.toThrow();
  });
});
