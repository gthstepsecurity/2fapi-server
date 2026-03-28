// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryRecoveryHashStore } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/in-memory-recovery-hash-store.js";

describe("InMemoryRecoveryHashStore", () => {
  it("stores and retrieves a hash", async () => {
    const store = new InMemoryRecoveryHashStore();
    const hash = new Uint8Array(32).fill(0xab);

    await store.storeHash("alice", hash);
    const retrieved = await store.getHash("alice");

    expect(retrieved).toEqual(hash);
  });

  it("returns null for unknown client", async () => {
    const store = new InMemoryRecoveryHashStore();

    const result = await store.getHash("unknown");

    expect(result).toBeNull();
  });

  it("overwrites existing hash on re-store", async () => {
    const store = new InMemoryRecoveryHashStore();
    const hash1 = new Uint8Array(32).fill(0xab);
    const hash2 = new Uint8Array(32).fill(0xcd);

    await store.storeHash("alice", hash1);
    await store.storeHash("alice", hash2);
    const retrieved = await store.getHash("alice");

    expect(retrieved).toEqual(hash2);
  });

  it("records failed attempts incrementally", async () => {
    const store = new InMemoryRecoveryHashStore();

    const count1 = await store.recordFailedAttempt("alice");
    const count2 = await store.recordFailedAttempt("alice");
    const count3 = await store.recordFailedAttempt("alice");

    expect(count1).toBe(1);
    expect(count2).toBe(2);
    expect(count3).toBe(3);
  });

  it("resets attempt counter to 0", async () => {
    const store = new InMemoryRecoveryHashStore();

    await store.recordFailedAttempt("alice");
    await store.recordFailedAttempt("alice");
    await store.resetAttempts("alice");

    // After reset, next attempt starts at 1 again
    const count = await store.recordFailedAttempt("alice");
    expect(count).toBe(1);
  });

  it("failed attempts are per-client", async () => {
    const store = new InMemoryRecoveryHashStore();

    await store.recordFailedAttempt("alice");
    await store.recordFailedAttempt("alice");
    const bobCount = await store.recordFailedAttempt("bob");

    expect(bobCount).toBe(1);
  });

  it("resetAttempts on unknown client does not throw", async () => {
    const store = new InMemoryRecoveryHashStore();

    await expect(store.resetAttempts("unknown")).resolves.toBeUndefined();
  });

  it("getAttemptCount returns 0 for unknown client", async () => {
    const store = new InMemoryRecoveryHashStore();

    const count = await store.getAttemptCount("unknown");

    expect(count).toBe(0);
  });

  it("getAttemptCount returns current failed attempts", async () => {
    const store = new InMemoryRecoveryHashStore();

    await store.recordFailedAttempt("alice");
    await store.recordFailedAttempt("alice");

    const count = await store.getAttemptCount("alice");
    expect(count).toBe(2);
  });

  it("deleteHash removes both hash and failed attempts", async () => {
    const store = new InMemoryRecoveryHashStore();
    const hash = new Uint8Array(32).fill(0xab);

    await store.storeHash("alice", hash);
    await store.recordFailedAttempt("alice");

    await store.deleteHash("alice");

    expect(await store.getHash("alice")).toBeNull();
    expect(await store.getAttemptCount("alice")).toBe(0);
  });

  it("deleteHash on unknown client does not throw", async () => {
    const store = new InMemoryRecoveryHashStore();

    await expect(store.deleteHash("unknown")).resolves.toBeUndefined();
  });
});
