// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  createRecoveryService,
  type RecoveryServiceDependencies,
} from "../../src/create-recovery-service.js";
import type { Argon2Hasher } from "../../src/client-registration/domain/port/outgoing/argon2-hasher.js";
import { StubArgon2Hasher } from "../../src/client-registration/infrastructure/adapter/outgoing/stub-argon2-hasher.js";
import { RealArgon2Hasher } from "../../src/client-registration/infrastructure/adapter/outgoing/real-argon2-hasher.js";
import {
  InMemoryClientRepository,
  InMemoryRecoveryHashStore,
  StubTokenInvalidator,
  StubChallengeInvalidator,
  StubAdminAuthenticator,
  RecoveryConfig,
} from "../../src/index.js";
import {
  createCapturingAuditLogger,
  createCapturingEventPublisher,
} from "../helpers/enrollment-test-helpers.js";

function baseDeps(argon2Hasher: Argon2Hasher, environment?: "development" | "test" | "production"): RecoveryServiceDependencies {
  return {
    clientRepository: new InMemoryClientRepository(),
    recoveryHashStore: new InMemoryRecoveryHashStore(),
    argon2Hasher,
    tokenInvalidator: new StubTokenInvalidator(),
    challengeInvalidator: new StubChallengeInvalidator(),
    auditLogger: createCapturingAuditLogger(),
    eventPublisher: createCapturingEventPublisher(),
    adminAuthenticator: new StubAdminAuthenticator(),
    recoveryConfig: RecoveryConfig.create({ recoveryMode: "phrase_only" }),
    reactivationProofVerifier: { verify: () => true },
    environment,
  };
}

describe("ITEM 1 — StubArgon2Hasher Fail-Fast Guard in createRecoveryService", () => {
  it("throws at startup when argon2Hasher is a StubArgon2Hasher in production", () => {
    const deps = baseDeps(new StubArgon2Hasher(), "production");
    expect(() => createRecoveryService(deps)).toThrow(
      "StubArgon2Hasher",
    );
  });

  it("allows StubArgon2Hasher in development", () => {
    const deps = baseDeps(new StubArgon2Hasher(), "development");
    const service = createRecoveryService(deps);
    expect(service.recoverViaPhrase).toBeDefined();
  });

  it("allows StubArgon2Hasher when environment is omitted", () => {
    const deps = baseDeps(new StubArgon2Hasher());
    const service = createRecoveryService(deps);
    expect(service.recoverViaPhrase).toBeDefined();
  });

  it("succeeds when a real Argon2Hasher is provided", () => {
    const deps = baseDeps(new RealArgon2Hasher(), "production");
    const service = createRecoveryService(deps);
    expect(service.recoverViaPhrase).toBeDefined();
    expect(service.reactivateViaExternal).toBeDefined();
  });
});
