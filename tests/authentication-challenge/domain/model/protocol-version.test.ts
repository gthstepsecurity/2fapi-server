// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ProtocolVersion } from "../../../../src/authentication-challenge/domain/model/protocol-version.js";

describe("ProtocolVersion", () => {
  it("should be created from a version string", () => {
    const version = ProtocolVersion.fromString("1.0");

    expect(version.value).toBe("1.0");
  });

  it("should reject an empty version string", () => {
    expect(() => ProtocolVersion.fromString("")).toThrow(
      "Protocol version must not be empty",
    );
  });

  it("should be equal to another ProtocolVersion with the same value", () => {
    const v1 = ProtocolVersion.fromString("1.0");
    const v2 = ProtocolVersion.fromString("1.0");

    expect(v1.equals(v2)).toBe(true);
  });

  it("should not be equal to a different version", () => {
    const v1 = ProtocolVersion.fromString("1.0");
    const v2 = ProtocolVersion.fromString("0.1-deprecated");

    expect(v1.equals(v2)).toBe(false);
  });
});
