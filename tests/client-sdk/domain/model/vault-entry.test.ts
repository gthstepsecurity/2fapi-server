// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VaultEntry } from "../../../../packages/client-sdk/src/domain/model/vault-entry.js";

describe("VaultEntry", () => {
  const validParams = {
    iv: new Uint8Array(12).fill(1),
    ciphertext: new Uint8Array(64).fill(2),
    tag: new Uint8Array(16).fill(3),
    deviceId: "dev-abc123def456",
    createdAtMs: 1711411200000,
    maxTtlHours: 72,
    version: 1,
  };

  it("creates a vault entry from valid parameters", () => {
    const entry = VaultEntry.create(validParams);
    expect(entry.deviceId).toBe("dev-abc123def456");
    expect(entry.version).toBe(1);
  });

  it("reports not expired when within TTL", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 48 * 60 * 60 * 1000; // +48h
    expect(entry.isExpired(nowMs)).toBe(false);
  });

  it("reports expired when past TTL", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 73 * 60 * 60 * 1000; // +73h
    expect(entry.isExpired(nowMs)).toBe(true);
  });

  it("reports exactly at TTL boundary as expired", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 72 * 60 * 60 * 1000; // exactly 72h
    expect(entry.isExpired(nowMs)).toBe(true);
  });

  it("computes remaining hours", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 66 * 60 * 60 * 1000; // +66h
    expect(entry.remainingHours(nowMs)).toBe(6);
  });

  it("returns 0 remaining hours when expired", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 80 * 60 * 60 * 1000;
    expect(entry.remainingHours(nowMs)).toBe(0);
  });

  it("indicates approaching expiry when less than 12 hours remain", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 65 * 60 * 60 * 1000; // 7h remaining
    expect(entry.isApproachingExpiry(nowMs)).toBe(true);
  });

  it("does not indicate approaching expiry when more than 12 hours remain", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 48 * 60 * 60 * 1000; // 24h remaining
    expect(entry.isApproachingExpiry(nowMs)).toBe(false);
  });

  it("serializes to a JSON-safe object", () => {
    const entry = VaultEntry.create(validParams);
    const serialized = entry.serialize();
    expect(serialized.deviceId).toBe("dev-abc123def456");
    expect(typeof serialized.iv).toBe("string"); // base64
    expect(typeof serialized.ciphertext).toBe("string");
    expect(typeof serialized.tag).toBe("string");
  });

  it("deserializes from a JSON-safe object", () => {
    const entry = VaultEntry.create(validParams);
    const serialized = entry.serialize();
    const restored = VaultEntry.deserialize(serialized);
    expect(restored.deviceId).toBe(entry.deviceId);
    expect(restored.createdAtMs).toBe(entry.createdAtMs);
    expect(restored.version).toBe(entry.version);
  });

  it("matches a specific email key", () => {
    const entry = VaultEntry.create(validParams);
    expect(entry.storageKey("alice@acme.com")).toBe("2fapi-vault:alice@acme.com");
  });

  it("reports not approaching expiry when expired", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 80 * 60 * 60 * 1000;
    expect(entry.isApproachingExpiry(nowMs)).toBe(false);
  });

  it("reports approaching expiry exactly at 11 hours remaining", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 61 * 60 * 60 * 1000; // 11h remaining
    expect(entry.isApproachingExpiry(nowMs)).toBe(true);
  });

  it("reports not approaching expiry at exactly 12 hours remaining", () => {
    const entry = VaultEntry.create(validParams);
    const nowMs = validParams.createdAtMs + 60 * 60 * 60 * 1000; // 12h remaining
    expect(entry.isApproachingExpiry(nowMs)).toBe(false);
  });

  it("serialization roundtrips byte content correctly", () => {
    const entry = VaultEntry.create(validParams);
    const serialized = entry.serialize();
    const restored = VaultEntry.deserialize(serialized);
    expect(restored.iv[0]).toBe(1);
    expect(restored.ciphertext[0]).toBe(2);
    expect(restored.tag[0]).toBe(3);
  });
});
