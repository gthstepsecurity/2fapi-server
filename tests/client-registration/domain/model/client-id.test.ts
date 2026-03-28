// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";

describe("ClientId", () => {
  it("wraps a 128-bit (16-byte) opaque identifier", () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 42;
    const id = ClientId.fromBytes(bytes);
    expect(id.toBytes()).toEqual(bytes);
  });

  it("rejects input shorter than 16 bytes", () => {
    const tooShort = new Uint8Array(15);
    expect(() => ClientId.fromBytes(tooShort)).toThrow("at least 16 bytes");
  });

  it("equals another ClientId with same bytes", () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 1;
    const a = ClientId.fromBytes(bytes);
    const b = ClientId.fromBytes(bytes);
    expect(a.equals(b)).toBe(true);
  });

  it("does not equal a ClientId with different bytes", () => {
    const a = ClientId.fromBytes(new Uint8Array(16).fill(1));
    const b = ClientId.fromBytes(new Uint8Array(16).fill(2));
    expect(a.equals(b)).toBe(false);
  });

  it("detects difference on the last byte only", () => {
    const a = ClientId.fromBytes(new Uint8Array(16).fill(1));
    const bytesB = new Uint8Array(16).fill(1);
    bytesB[15] = 2;
    const b = ClientId.fromBytes(bytesB);
    expect(a.equals(b)).toBe(false);
  });

  it("toString returns an opaque hex string, not raw bytes", () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 0xff;
    const id = ClientId.fromBytes(bytes);
    expect(id.toString()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("equals returns false for different length ClientIds (length guard)", () => {
    // Kill mutant: `if (false) return false` instead of length check
    // and `i <= this.bytes.length` instead of `i < this.bytes.length`
    const a = ClientId.fromBytes(new Uint8Array(16).fill(0));
    const b = ClientId.fromBytes(new Uint8Array(32).fill(0));
    expect(a.equals(b)).toBe(false);
  });

  it("equals loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= this.bytes.length; i++)` — off-by-one
    const a = ClientId.fromBytes(new Uint8Array(16).fill(1));
    const b = ClientId.fromBytes(new Uint8Array(16).fill(1));
    expect(a.equals(b)).toBe(true);
  });
});
