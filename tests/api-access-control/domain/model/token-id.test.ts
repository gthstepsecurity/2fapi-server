// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { TokenId } from "../../../../src/api-access-control/domain/model/token-id.js";

describe("TokenId", () => {
  it("creates from a non-empty string", () => {
    const id = TokenId.fromString("tok-abc-123");
    expect(id.value).toBe("tok-abc-123");
  });

  it("rejects empty string", () => {
    expect(() => TokenId.fromString("")).toThrow("Token ID must not be empty");
  });

  it("equals another TokenId with same value", () => {
    const a = TokenId.fromString("tok-001");
    const b = TokenId.fromString("tok-001");
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal a TokenId with different value", () => {
    const a = TokenId.fromString("tok-001");
    const b = TokenId.fromString("tok-002");
    expect(a.equals(b)).toBe(false);
  });

  it("toString returns the value", () => {
    const id = TokenId.fromString("tok-xyz");
    expect(id.toString()).toBe("tok-xyz");
  });
});
