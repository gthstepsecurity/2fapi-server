// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, vi } from "vitest";
import { ConfigAuthorizationChecker } from "../../src/api-access-control/infrastructure/adapter/outgoing/config-authorization-checker.js";

/**
 * Sprint 17 — Finding 6 (LOW): ConfigAuthorizationChecker Open by Default
 *
 * When no audience configuration is provided (allowedAudiences = null),
 * the checker was returning true (allow all). This is a fail-open default.
 *
 * Fix: When no config, return false (deny all). Log a warning at construction.
 */

describe("AuthorizationChecker Deny-All Default", () => {
  it("should deny all requests when no audience config is provided", async () => {
    const checker = new ConfigAuthorizationChecker();
    const result = await checker.isAuthorized("any-client", "any-audience");
    expect(result).toBe(false);
  });

  it("should deny all requests when undefined config is provided", async () => {
    const checker = new ConfigAuthorizationChecker(undefined);
    const result = await checker.isAuthorized("client-1", "payment-api");
    expect(result).toBe(false);
  });

  it("should allow matching audience when config is provided", async () => {
    const checker = new ConfigAuthorizationChecker({
      "client-1": ["payment-api", "user-api"],
    });
    const result = await checker.isAuthorized("client-1", "payment-api");
    expect(result).toBe(true);
  });

  it("should deny non-matching audience when config is provided", async () => {
    const checker = new ConfigAuthorizationChecker({
      "client-1": ["payment-api"],
    });
    const result = await checker.isAuthorized("client-1", "admin-api");
    expect(result).toBe(false);
  });

  it("should deny unknown client when config is provided", async () => {
    const checker = new ConfigAuthorizationChecker({
      "client-1": ["payment-api"],
    });
    const result = await checker.isAuthorized("unknown-client", "payment-api");
    expect(result).toBe(false);
  });

  it("should log a warning when constructed without audience config", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    new ConfigAuthorizationChecker();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("no audience"),
    );
    warnSpy.mockRestore();
  });
});
