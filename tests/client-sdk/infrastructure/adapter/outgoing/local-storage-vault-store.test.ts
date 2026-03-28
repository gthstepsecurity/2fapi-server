// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { LocalStorageVaultStore } from "../../../../../packages/client-sdk/src/infrastructure/adapter/outgoing/local-storage-vault-store.js";
import { VaultEntry } from "../../../../../packages/client-sdk/src/domain/model/vault-entry.js";

// --- In-memory localStorage stub ---

function createMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => { store.set(key, value); },
    removeItem: (key) => { store.delete(key); },
    clear: () => store.clear(),
    get length() { return store.size; },
    key: (index) => [...store.keys()][index] ?? null,
  };
}

function makeEntry(deviceId = "dev-abc123"): VaultEntry {
  return VaultEntry.create({
    iv: new Uint8Array(12).fill(1),
    ciphertext: new Uint8Array(64).fill(2),
    tag: new Uint8Array(16).fill(3),
    deviceId,
    createdAtMs: 1711411200000,
    maxTtlHours: 72,
    version: 1,
  });
}

describe("LocalStorageVaultStore", () => {
  let storage: Storage;
  let store: LocalStorageVaultStore;

  beforeEach(() => {
    storage = createMemoryStorage();
    store = new LocalStorageVaultStore(storage);
  });

  it("saves and loads a vault entry", () => {
    const entry = makeEntry();
    store.save("alice@acme.com", entry);

    const loaded = store.load("alice@acme.com");
    expect(loaded).not.toBeNull();
    expect(loaded!.deviceId).toBe("dev-abc123");
  });

  it("returns null for non-existent email", () => {
    expect(store.load("nobody@acme.com")).toBeNull();
  });

  it("reports existence correctly", () => {
    expect(store.exists("alice@acme.com")).toBe(false);
    store.save("alice@acme.com", makeEntry());
    expect(store.exists("alice@acme.com")).toBe(true);
  });

  it("deletes a vault entry", () => {
    store.save("alice@acme.com", makeEntry());
    store.delete("alice@acme.com");
    expect(store.load("alice@acme.com")).toBeNull();
  });

  it("preserves other emails when deleting one", () => {
    store.save("alice@acme.com", makeEntry("dev-alice"));
    store.save("bob@acme.com", makeEntry("dev-bob"));
    store.delete("alice@acme.com");

    expect(store.load("alice@acme.com")).toBeNull();
    expect(store.load("bob@acme.com")).not.toBeNull();
    expect(store.load("bob@acme.com")!.deviceId).toBe("dev-bob");
  });

  it("roundtrips all vault entry fields", () => {
    const entry = makeEntry();
    store.save("alice@acme.com", entry);
    const loaded = store.load("alice@acme.com")!;

    expect(loaded.createdAtMs).toBe(entry.createdAtMs);
    expect(loaded.maxTtlHours).toBe(entry.maxTtlHours);
    expect(loaded.version).toBe(entry.version);
    expect(loaded.iv.length).toBe(12);
    expect(loaded.ciphertext.length).toBe(64);
    expect(loaded.tag.length).toBe(16);
  });

  it("overwrites existing vault for same email", () => {
    store.save("alice@acme.com", makeEntry("dev-old"));
    store.save("alice@acme.com", makeEntry("dev-new"));

    const loaded = store.load("alice@acme.com")!;
    expect(loaded.deviceId).toBe("dev-new");
  });

  it("handles corrupted JSON gracefully", () => {
    storage.setItem("2fapi-vault:alice@acme.com", "not-valid-json{{{");
    expect(store.load("alice@acme.com")).toBeNull();
  });

  it("uses the correct storage key format", () => {
    store.save("alice@acme.com", makeEntry());
    expect(storage.getItem("2fapi-vault:alice@acme.com")).not.toBeNull();
  });
});
