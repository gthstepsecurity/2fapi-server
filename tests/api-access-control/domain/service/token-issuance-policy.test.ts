// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  TokenIssuancePolicy,
  type IssuancePreconditions,
} from "../../../../src/api-access-control/domain/service/token-issuance-policy.js";

function validPreconditions(
  overrides: Partial<IssuancePreconditions> = {},
): IssuancePreconditions {
  return {
    clientActive: overrides.clientActive ?? true,
    clientAuthorized: overrides.clientAuthorized ?? true,
  };
}

describe("TokenIssuancePolicy", () => {
  const policy = new TokenIssuancePolicy();

  it("returns null when client is active and authorized", () => {
    const error = policy.validate(validPreconditions());
    expect(error).toBeNull();
  });

  it("returns CLIENT_NOT_ACTIVE when client is not active", () => {
    const error = policy.validate(
      validPreconditions({ clientActive: false }),
    );
    expect(error).not.toBeNull();
    expect(error!.code).toBe("CLIENT_NOT_ACTIVE");
    expect(error!.message).toBe("Client is not active");
    expect(error!.name).toBe("IssuancePolicyError");
  });

  it("returns CLIENT_NOT_AUTHORIZED when client is not authorized for audience", () => {
    const error = policy.validate(
      validPreconditions({ clientAuthorized: false }),
    );
    expect(error).not.toBeNull();
    expect(error!.code).toBe("CLIENT_NOT_AUTHORIZED");
    expect(error!.message).toBe("Client is not authorized for the requested audience");
    expect(error!.name).toBe("IssuancePolicyError");
  });

  it("checks client active BEFORE authorization", () => {
    // Both fail, but CLIENT_NOT_ACTIVE should be returned first
    const error = policy.validate(
      validPreconditions({ clientActive: false, clientAuthorized: false }),
    );
    expect(error!.code).toBe("CLIENT_NOT_ACTIVE");
  });
});
