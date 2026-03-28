// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VaultPepper } from "../../../../packages/client-sdk/src/domain/model/vault-pepper.js";

describe("VaultPepper", () => {
  it("generates a 32-byte random pepper", () => {
    const pepper = VaultPepper.generate("client-1", "dev-abc123");
    expect(pepper.value.length).toBe(32);
    expect(pepper.value.some(b => b !== 0)).toBe(true);
  });

  it("generates different peppers each time", () => {
    const p1 = VaultPepper.generate("client-1", "dev-abc123");
    const p2 = VaultPepper.generate("client-1", "dev-abc123");
    expect(Buffer.from(p1.value).equals(Buffer.from(p2.value))).toBe(false);
  });

  it("stores clientId and deviceId", () => {
    const pepper = VaultPepper.generate("client-alice", "dev-laptop");
    expect(pepper.clientId).toBe("client-alice");
    expect(pepper.deviceId).toBe("dev-laptop");
  });

  it("can be destroyed (zeroized)", () => {
    const pepper = VaultPepper.generate("client-1", "dev-abc123");
    expect(pepper.isDestroyed).toBe(false);

    const destroyed = pepper.destroy();
    expect(destroyed.isDestroyed).toBe(true);
    expect(destroyed.value.every(b => b === 0)).toBe(true);
  });

  it("restores from stored bytes", () => {
    const bytes = new Uint8Array(32).fill(0xCC);
    const pepper = VaultPepper.restore("client-1", "dev-abc123", bytes, false);
    expect(pepper.value[0]).toBe(0xCC);
    expect(pepper.isDestroyed).toBe(false);
  });

  it("throws when accessing destroyed pepper's value for derivation", () => {
    const pepper = VaultPepper.generate("client-1", "dev-abc123").destroy();
    expect(() => pepper.valueForDerivation()).toThrow("Pepper has been destroyed");
  });

  it("returns value for derivation when not destroyed", () => {
    const pepper = VaultPepper.generate("client-1", "dev-abc123");
    const val = pepper.valueForDerivation();
    expect(val.length).toBe(32);
  });
});
