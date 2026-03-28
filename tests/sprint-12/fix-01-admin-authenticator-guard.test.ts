// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { createLifecycleService, type LifecycleServiceDependencies } from "../../src/create-lifecycle-service.js";
import type { AdminAuthenticator } from "../../src/client-registration/domain/port/outgoing/admin-authenticator.js";
import { StubAdminAuthenticator } from "../../src/client-registration/infrastructure/adapter/outgoing/stub-admin-authenticator.js";
import {
  InMemoryClientRepository,
  StubCommitmentVerifier,
  StubRotationProofVerifier,
  StubTokenInvalidator,
  StubChallengeInvalidator,
  NoopRateLimiter,
} from "../../src/index.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../helpers/enrollment-test-helpers.js";

class RealAdminAuthenticator implements AdminAuthenticator {
  async isValidAdmin(adminIdentity: string): Promise<boolean> {
    return adminIdentity === "real-admin";
  }
}

function baseDeps(authenticator?: AdminAuthenticator, environment?: "development" | "test" | "production"): LifecycleServiceDependencies {
  return {
    clientRepository: new InMemoryClientRepository(),
    commitmentVerifier: new StubCommitmentVerifier(),
    rotationProofVerifier: new StubRotationProofVerifier(true),
    tokenInvalidator: new StubTokenInvalidator(),
    challengeInvalidator: new StubChallengeInvalidator(),
    auditLogger: createCapturingAuditLogger(),
    eventPublisher: createCapturingEventPublisher(),
    adminAuthenticator: authenticator as AdminAuthenticator,
    rateLimiter: new NoopRateLimiter(),
    environment,
  };
}

describe("FIX 1 — StubAdminAuthenticator Fail-Fast Guard", () => {
  it("throws at startup when adminAuthenticator is undefined in production", () => {
    const deps = baseDeps(undefined, "production");
    expect(() => createLifecycleService(deps)).toThrow(
      "AdminAuthenticator is required",
    );
  });

  it("throws at startup when adminAuthenticator is null in production", () => {
    const deps = baseDeps(null as unknown as AdminAuthenticator, "production");
    expect(() => createLifecycleService(deps)).toThrow(
      "AdminAuthenticator is required",
    );
  });

  it("throws at startup when adminAuthenticator is a StubAdminAuthenticator in production", () => {
    const deps = baseDeps(new StubAdminAuthenticator(), "production");
    expect(() => createLifecycleService(deps)).toThrow(
      "never deploy with StubAdminAuthenticator",
    );
  });

  it("allows StubAdminAuthenticator in development", () => {
    const deps = baseDeps(new StubAdminAuthenticator(), "development");
    const service = createLifecycleService(deps);
    expect(service.revokeClient).toBeDefined();
  });

  it("allows StubAdminAuthenticator when environment is omitted", () => {
    const deps = baseDeps(new StubAdminAuthenticator());
    const service = createLifecycleService(deps);
    expect(service.revokeClient).toBeDefined();
  });

  it("succeeds when a real AdminAuthenticator is provided in production", () => {
    const deps = baseDeps(new RealAdminAuthenticator(), "production");
    const service = createLifecycleService(deps);
    expect(service.revokeClient).toBeDefined();
    expect(service.rotateCommitment).toBeDefined();
  });
});
