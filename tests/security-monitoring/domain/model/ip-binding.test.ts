// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { IpBinding } from "../../../../src/security-monitoring/domain/model/ip-binding.js";

describe("IpBinding", () => {
  it("creates a binding with clientIdentifier, sourceIp, and boundAtMs", () => {
    const binding = IpBinding.create("alice-payment-service", "203.0.113.10", 1700000000000);

    expect(binding.clientIdentifier).toBe("alice-payment-service");
    expect(binding.sourceIp).toBe("203.0.113.10");
    expect(binding.boundAtMs).toBe(1700000000000);
  });

  it("is immutable — frozen after creation", () => {
    const binding = IpBinding.create("alice", "10.0.0.1", 1000);
    expect(Object.isFrozen(binding)).toBe(true);
  });

  it("rejects empty clientIdentifier", () => {
    expect(() => IpBinding.create("", "10.0.0.1", 1000)).toThrow(
      "Client identifier must not be empty",
    );
  });

  it("rejects empty sourceIp", () => {
    expect(() => IpBinding.create("alice", "", 1000)).toThrow(
      "Source IP must not be empty",
    );
  });

  it("rejects negative boundAtMs", () => {
    expect(() => IpBinding.create("alice", "10.0.0.1", -1)).toThrow(
      "Bound timestamp must be non-negative",
    );
  });

  it("two bindings with same values are equal", () => {
    const a = IpBinding.create("alice", "10.0.0.1", 1000);
    const b = IpBinding.create("alice", "10.0.0.1", 1000);
    expect(a.equals(b)).toBe(true);
  });

  it("two bindings with different values are not equal", () => {
    const a = IpBinding.create("alice", "10.0.0.1", 1000);
    const b = IpBinding.create("alice", "10.0.0.2", 1000);
    expect(a.equals(b)).toBe(false);
  });
});
