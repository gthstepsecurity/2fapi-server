// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { TierDetector } from "../../../../packages/client-sdk/src/domain/service/tier-detector.js";
import { DeviceContext } from "../../../../packages/client-sdk/src/domain/model/device-context.js";
import { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";
import type { VaultLocalStore } from "../../../../packages/client-sdk/src/domain/port/outgoing/vault-local-store.js";

function makeEntry(expired = false): VaultEntry {
  return VaultEntry.create({
    iv: new Uint8Array(12), ciphertext: new Uint8Array(64), tag: new Uint8Array(16),
    deviceId: "dev-1", createdAtMs: expired ? Date.now() - 73 * 3600000 : Date.now(),
    maxTtlHours: 72, version: 1,
  });
}

function stubStore(entry: VaultEntry | null): VaultLocalStore {
  return {
    save: () => {}, load: () => entry, delete: () => {},
    exists: () => entry !== null,
  };
}

describe("TierDetector", () => {
  it("shared device always returns Tier 0", async () => {
    const detector = new TierDetector(stubStore(makeEntry()), async () => true);
    const result = await detector.detect("alice@acme.com", DeviceContext.shared());
    expect(result.tier).toBe(0);
  });

  it("biometric available returns Tier 2", async () => {
    const detector = new TierDetector(stubStore(null), async () => true);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(2);
  });

  it("vault exists returns Tier 1 when no biometric", async () => {
    const detector = new TierDetector(stubStore(makeEntry()), async () => false);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(1);
  });

  it("nothing available returns Tier 0", async () => {
    const detector = new TierDetector(stubStore(null), async () => false);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(0);
  });

  it("expired vault falls through to Tier 0", async () => {
    const detector = new TierDetector(stubStore(makeEntry(true)), async () => false);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(0);
  });

  it("biometric error falls through to vault check", async () => {
    const detector = new TierDetector(stubStore(makeEntry()), async () => { throw new Error("hw"); });
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(1);
  });

  it("Tier 2 includes credential ID", async () => {
    const detector = new TierDetector(stubStore(null), async () => true);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    expect(result.tier).toBe(2);
    if (result.tier === 2) expect(result.credentialId).toContain("alice@acme.com");
  });

  it("Tier 1 includes device ID from vault", async () => {
    const detector = new TierDetector(stubStore(makeEntry()), async () => false);
    const result = await detector.detect("alice@acme.com", DeviceContext.personal());
    if (result.tier === 1) expect(result.deviceId).toBe("dev-1");
  });
});
