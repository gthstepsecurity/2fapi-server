// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DeviceContextDetector } from "../../../../packages/client-sdk/src/domain/service/device-context-detector.js";

describe("DeviceContextDetector", () => {
  const detector = new DeviceContextDetector();

  // --- Admin policy enforcement ---

  it("admin shared_enforced overrides everything", () => {
    const ctx = detector.detect({ tenantPolicy: "shared_enforced", userDeclaredMode: "personal" });
    expect(ctx.isShared).toBe(true);
    expect(ctx.detectionMethod).toBe("admin_enforced");
  });

  it("admin personal_enforced overrides heuristics", () => {
    const ctx = detector.detect({ tenantPolicy: "personal_enforced", isKioskMode: true });
    expect(ctx.isPersonal).toBe(true);
    expect(ctx.detectionMethod).toBe("admin_enforced");
  });

  // --- User declaration ---

  it("user declared shared is respected", () => {
    const ctx = detector.detect({ userDeclaredMode: "shared" });
    expect(ctx.isShared).toBe(true);
    expect(ctx.detectionMethod).toBe("user_declared");
  });

  it("user declared personal is respected", () => {
    const ctx = detector.detect({ userDeclaredMode: "personal" });
    expect(ctx.isPersonal).toBe(true);
  });

  // --- Auto-detection heuristics ---

  it("kiosk mode auto-detected as shared", () => {
    const ctx = detector.detect({ isKioskMode: true });
    expect(ctx.isShared).toBe(true);
    expect(ctx.mode).toBe("kiosk");
  });

  it("remote desktop auto-detected as shared", () => {
    const ctx = detector.detect({ isRemoteDesktop: true });
    expect(ctx.isShared).toBe(true);
    expect(ctx.detectionMethod).toBe("auto_detected");
  });

  it("multiple accounts auto-detected as shared", () => {
    const ctx = detector.detect({ hasMultipleAccounts: true });
    expect(ctx.isShared).toBe(true);
  });

  it("localStorage unavailable defaults to shared", () => {
    const ctx = detector.detect({ localStorageUnavailable: true });
    expect(ctx.isShared).toBe(true);
  });

  // --- Default ---

  it("defaults to personal when no signals", () => {
    const ctx = detector.detect({});
    expect(ctx.isPersonal).toBe(true);
  });

  // --- Permission checks ---

  it("shared device does not allow persistence", () => {
    const ctx = detector.detect({ userDeclaredMode: "shared" });
    expect(ctx.allowsPersistence).toBe(false);
    expect(ctx.allowsBiometric).toBe(false);
    expect(ctx.allowsVault).toBe(false);
  });

  it("personal device allows all storage tiers", () => {
    const ctx = detector.detect({ userDeclaredMode: "personal" });
    expect(ctx.allowsPersistence).toBe(true);
    expect(ctx.allowsBiometric).toBe(true);
    expect(ctx.allowsVault).toBe(true);
  });
});
