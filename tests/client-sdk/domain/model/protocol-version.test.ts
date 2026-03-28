// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ProtocolVersion } from "../../../../packages/client-sdk/src/domain/model/protocol-version.js";

describe("ProtocolVersion", () => {
  it("current version is 1.0", () => {
    expect(ProtocolVersion.CURRENT.toString()).toBe("1.0");
  });

  it("parses valid version string", () => {
    const v = ProtocolVersion.parse("2.1");
    expect(v).not.toBeNull();
    expect(v!.major).toBe(2);
    expect(v!.minor).toBe(1);
  });

  it("returns null for invalid version string", () => {
    expect(ProtocolVersion.parse("abc")).toBeNull();
    expect(ProtocolVersion.parse("")).toBeNull();
    expect(ProtocolVersion.parse("1")).toBeNull();
  });

  it("rejects version 0.x (reserved)", () => {
    expect(ProtocolVersion.parse("0.0")).toBeNull();
    expect(ProtocolVersion.parse("0.1")).toBeNull();
  });

  it("same major version is compatible", () => {
    const v1 = ProtocolVersion.parse("1.0")!;
    const v2 = ProtocolVersion.parse("1.5")!;
    expect(v1.isCompatibleWith(v2)).toBe(true);
  });

  it("different major version is incompatible", () => {
    const v1 = ProtocolVersion.parse("1.0")!;
    const v2 = ProtocolVersion.parse("2.0")!;
    expect(v1.isCompatibleWith(v2)).toBe(false);
  });
});
