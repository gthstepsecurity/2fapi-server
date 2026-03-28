// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RevocationPolicy } from "../../../../src/client-registration/domain/service/revocation-policy.js";

describe("RevocationPolicy", () => {
  const policy = new RevocationPolicy();

  it("returns null when admin identity is present", () => {
    const error = policy.validate("admin-alice");
    expect(error).toBeNull();
  });

  it("returns error when admin identity is empty", () => {
    const error = policy.validate("");
    expect(error).not.toBeNull();
    expect(error!.code).toBe("MISSING_ADMIN_IDENTITY");
    expect(error!.message).toBe("Admin identity is required for revocation");
    expect(error!.name).toBe("LifecycleError");
  });

  it("returns error when admin identity is whitespace-only", () => {
    const error = policy.validate("   ");
    expect(error).not.toBeNull();
    expect(error!.code).toBe("MISSING_ADMIN_IDENTITY");
    expect(error!.message).toBe("Admin identity is required for revocation");
  });
});
