// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import type { RecoveryHashStore } from "../../../../../src/client-registration/domain/port/outgoing/recovery-hash-store.js";

describe("RecoveryHashStore port", () => {
  it("defines storeHash method", () => {
    const store: RecoveryHashStore = {
      storeHash: async () => {},
      getHash: async () => null,
      recordFailedAttempt: async () => 0,
      resetAttempts: async () => {},
    };

    expect(store.storeHash).toBeDefined();
  });

  it("defines getHash method returning Uint8Array or null", async () => {
    const hash = new Uint8Array(32).fill(0xab);
    const store: RecoveryHashStore = {
      storeHash: async () => {},
      getHash: async () => hash,
      recordFailedAttempt: async () => 0,
      resetAttempts: async () => {},
    };

    const result = await store.getHash("alice-payment-service");
    expect(result).toEqual(hash);
  });

  it("defines getHash method returning null when no hash stored", async () => {
    const store: RecoveryHashStore = {
      storeHash: async () => {},
      getHash: async () => null,
      recordFailedAttempt: async () => 0,
      resetAttempts: async () => {},
    };

    const result = await store.getHash("unknown-client");
    expect(result).toBeNull();
  });

  it("defines recordFailedAttempt returning current attempt count", async () => {
    const store: RecoveryHashStore = {
      storeHash: async () => {},
      getHash: async () => null,
      recordFailedAttempt: async () => 1,
      resetAttempts: async () => {},
    };

    const count = await store.recordFailedAttempt("alice-payment-service");
    expect(count).toBe(1);
  });

  it("defines resetAttempts method", () => {
    const store: RecoveryHashStore = {
      storeHash: async () => {},
      getHash: async () => null,
      recordFailedAttempt: async () => 0,
      resetAttempts: async () => {},
    };

    expect(store.resetAttempts).toBeDefined();
  });
});
