// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PgClientStatusBridge } from "../../src/authentication-challenge/infrastructure/adapter/outgoing/pg-client-status-bridge.js";

/**
 * Sprint 17 — Finding 5 (MEDIUM): Lockout Check Fail-Open on DB Error
 *
 * When the database is unavailable, the lockout check was returning
 * { isLockedOut: false, failedAttempts: 0 } (fail-open), which allows
 * an attacker to bypass lockout by overloading the database.
 *
 * Fix: Return { isLockedOut: true, failedAttempts: 999 } on DB error (fail-closed).
 */

describe("Lockout Check Fail-Closed", () => {
  it("should return locked-out status when database query throws", async () => {
    const failingDb = {
      query: async () => {
        throw new Error("Connection pool exhausted");
      },
    };

    const bridge = new PgClientStatusBridge(failingDb);
    const result = await bridge.getLockoutInfo("alice");

    expect(result.isLockedOut).toBe(true);
  });

  it("should return high failed attempts count when database is down", async () => {
    const failingDb = {
      query: async () => {
        throw new Error("ECONNREFUSED");
      },
    };

    const bridge = new PgClientStatusBridge(failingDb);
    const result = await bridge.getLockoutInfo("bob");

    expect(result.failedAttempts).toBeGreaterThanOrEqual(999);
  });

  it("should still return not-locked-out for client with no failed attempts", async () => {
    const emptyDb = {
      query: async () => ({ rows: [] }),
    };

    const bridge = new PgClientStatusBridge(emptyDb);
    const result = await bridge.getLockoutInfo("clean-client");

    expect(result.isLockedOut).toBe(false);
    expect(result.failedAttempts).toBe(0);
  });

  it("should detect lockout when locked_out_at_ms is recent", async () => {
    const lockedDb = {
      query: async () => ({
        rows: [{
          consecutive_failures: 5,
          locked_out_at_ms: String(Date.now() - 1000), // 1 second ago
        }],
      }),
    };

    const bridge = new PgClientStatusBridge(lockedDb, 900_000);
    const result = await bridge.getLockoutInfo("locked-client");

    expect(result.isLockedOut).toBe(true);
    expect(result.failedAttempts).toBe(5);
  });

  it("should detect expired lockout when enough time has passed", async () => {
    const expiredDb = {
      query: async () => ({
        rows: [{
          consecutive_failures: 3,
          locked_out_at_ms: String(Date.now() - 1_000_000), // >15 min ago
        }],
      }),
    };

    const bridge = new PgClientStatusBridge(expiredDb, 900_000);
    const result = await bridge.getLockoutInfo("expired-client");

    expect(result.isLockedOut).toBe(false);
    expect(result.failedAttempts).toBe(3);
  });
});
