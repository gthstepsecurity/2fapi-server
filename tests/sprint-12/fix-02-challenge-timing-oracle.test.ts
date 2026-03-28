// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RequestChallengeUseCase } from "../../src/authentication-challenge/application/usecase/request-challenge.usecase.js";
import { ChallengeIssuancePolicy } from "../../src/authentication-challenge/domain/service/challenge-issuance-policy.js";
import { ProtocolVersion } from "../../src/authentication-challenge/domain/model/protocol-version.js";
import {
  createStubNonceGenerator,
  createStubCredentialVerifier,
  createStubClientStatusChecker,
  createStubRateLimiter,
  createCapturingAuditLogger,
  createCapturingEventPublisher,
  createStubClock,
  createStubIdGenerator,
  createInMemoryChallengeRepository,
  validChallengeRequest,
} from "../helpers/challenge-test-helpers.js";

const SUPPORTED_VERSIONS = [ProtocolVersion.fromString("1.0")];
const TTL_MS = 2 * 60 * 1000;

describe("FIX 2 — Challenge Request Timing Oracle Mitigation", () => {
  it("calls capacityPercentage on failure path (invalid credential)", async () => {
    let capacityCalled = false;
    const repository = createInMemoryChallengeRepository();
    const originalCapacity = repository.capacityPercentage;
    repository.capacityPercentage = async () => {
      capacityCalled = true;
      return originalCapacity.call(repository);
    };

    const policy = new ChallengeIssuancePolicy(SUPPORTED_VERSIONS, false);
    const useCase = new RequestChallengeUseCase(
      createStubCredentialVerifier({ valid: false }),
      createStubClientStatusChecker(),
      createStubRateLimiter(),
      repository,
      createStubNonceGenerator(),
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createStubClock(),
      policy,
      TTL_MS,
    );

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    expect(capacityCalled).toBe(true);
  });

  it("calls findPendingByClientIdentifier on failure path (invalid credential)", async () => {
    let findPendingCalled = false;
    const repository = createInMemoryChallengeRepository();
    const originalFind = repository.findPendingByClientIdentifier;
    repository.findPendingByClientIdentifier = async (clientIdentifier: string) => {
      findPendingCalled = true;
      return originalFind.call(repository, clientIdentifier);
    };

    const policy = new ChallengeIssuancePolicy(SUPPORTED_VERSIONS, false);
    const useCase = new RequestChallengeUseCase(
      createStubCredentialVerifier({ valid: false }),
      createStubClientStatusChecker(),
      createStubRateLimiter(),
      repository,
      createStubNonceGenerator(),
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createStubClock(),
      policy,
      TTL_MS,
    );

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    expect(findPendingCalled).toBe(true);
  });

  it("calls capacityPercentage on failure path (revoked client)", async () => {
    let capacityCalled = false;
    const repository = createInMemoryChallengeRepository();
    repository.capacityPercentage = async () => {
      capacityCalled = true;
      return 0;
    };

    const policy = new ChallengeIssuancePolicy(SUPPORTED_VERSIONS, false);
    const useCase = new RequestChallengeUseCase(
      createStubCredentialVerifier({ clientStatus: "revoked", valid: true }),
      createStubClientStatusChecker(),
      createStubRateLimiter(),
      repository,
      createStubNonceGenerator(),
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createStubClock(),
      policy,
      TTL_MS,
    );

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    expect(capacityCalled).toBe(true);
  });

  it("calls findPendingByClientIdentifier on failure path (locked-out client)", async () => {
    let findPendingCalled = false;
    const repository = createInMemoryChallengeRepository();
    repository.findPendingByClientIdentifier = async (clientIdentifier: string) => {
      findPendingCalled = true;
      return null;
    };

    const policy = new ChallengeIssuancePolicy(SUPPORTED_VERSIONS, false);
    const useCase = new RequestChallengeUseCase(
      createStubCredentialVerifier({ valid: true }),
      createStubClientStatusChecker({ isLockedOut: true }),
      createStubRateLimiter(),
      repository,
      createStubNonceGenerator(),
      createStubIdGenerator(),
      createCapturingAuditLogger(),
      createCapturingEventPublisher(),
      createStubClock(),
      policy,
      TTL_MS,
    );

    const result = await useCase.execute(validChallengeRequest());

    expect(result.success).toBe(false);
    expect(findPendingCalled).toBe(true);
  });
});
